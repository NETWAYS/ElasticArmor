# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import socket
import time
import threading

import ldap
import requests

from elasticarmor.util import format_ldap_error, format_elasticsearch_error, pattern_match, pattern_compare
from elasticarmor.util.elastic import ElasticSearchError, ElasticRole, SourceFilter
from elasticarmor.util.mixins import LoggingAware
from elasticarmor.util.rwlock import ReadWriteLock, Protector

__all__ = ['AuthorizationError', 'Auth', 'Client', 'RestrictionError', 'Restriction', 'LdapBackend',
           'LdapUserBackend', 'LdapUsergroupBackend', 'ElasticsearchRoleBackend']

CACHE_INVALIDATION_INTERVAL = 900  # Seconds


class AuthorizationError(Exception):
    """Base class for all authorization related exceptions."""
    pass


class Auth(LoggingAware, object):
    """Auth manager class for everything involved in authentication and authorization."""

    def __init__(self, settings):
        self.allow_from = settings.allow_from
        self.role_backend = settings.role_backend
        self.auth_backends = settings.auth_backends
        self.group_backends = settings.group_backends

    def authenticate(self, client, populate=True):
        """Authenticate the given client and return whether it succeeded or not."""
        if client.username is None or client.password is None:
            # In case we have no authentication credentials check if access by ip[:port] is permitted
            allowed_ports = self.allow_from.get(client.address, [])
            if allowed_ports is not None and client.port not in allowed_ports:
                return False
            else:
                default_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(2)

                try:
                    hostname = socket.gethostbyaddr(client.address)[0]
                except IOError:
                    hostname = client.address
                finally:
                    socket.setdefaulttimeout(default_timeout)

                client.name = hostname if allowed_ports is None else '%s:%u' % (hostname, client.port)
                client.authenticated = True
        else:
            client.name = client.username
            if self.auth_backends:
                for backend in self.auth_backends:
                    try:
                        if backend.authenticate(client):
                            client.authenticated = True
                            break
                    except ldap.LDAPError as error:
                        self.log.error('Failed to authenticate client "%s" using backend "%s". %s.',
                                       client, backend.name, format_ldap_error(error))
            else:
                client.authenticated = True

        if client.authenticated and populate:
            self.populate(client)

        return client.authenticated

    def populate(self, client):
        """Populate the group and role memberships of the given client."""
        if self.group_backends and client.username is not None:
            self.log.debug('Fetching group memberships for client "%s"...', client)

            groups, error = [], None
            for backend in self.group_backends:
                try:
                    groups.extend(backend.get_group_memberships(client))
                except ldap.LDAPError as error:
                    self.log.error('Failed to fetch ldap group memberships for client "%s" using backend "%s". %s.',
                                   client, backend.name, format_ldap_error(error))

            if groups or error is None:
                client.groups = groups
                self.log.debug('Client "%s" is a member of the following groups: %s',
                               client, ', '.join(client.groups) or 'None')
        else:
            client.groups = []

        if client.groups is not None:
            self.log.debug('Fetching role memberships for client "%s"...', client)

            try:
                client.roles = self.role_backend.get_role_memberships(client)
            except requests.RequestException as error:
                self.log.error('Failed to fetch Elasticsearch role memberships for client "%s". Error: %s',
                               client, format_elasticsearch_error(error))
            else:
                self.log.debug('Client "%s" is a member of the following roles: %s',
                               client, ', '.join(r.name for r in client.roles) or 'None')


class Client(object):
    """An object representing a client who is sending a request."""

    def __init__(self, address, port):
        self.address = address
        self.port = port

        self.name = None
        self.authenticated = False
        self.username = None
        self.password = None
        self.groups = None
        self.roles = None

    def __str__(self):
        """Return a human readable string representation for this client.
        That's either the name, username or the address and port concatenated with a colon."""
        if self.name is not None:
            return self.name

        if self.username is not None:
            return self.username

        return '%s:%u' % (self.address, self.port)

    def is_restricted(self):
        """Return whether this client is restricted."""
        return any(role.restrictions for role in self.roles)

    def can(self, permission):
        """Return whether this client has the given permission."""
        return any(permission.startswith(p) for r in self.roles for p in r.permissions)

    def can_read(self, index, document=None, field=None):
        """Return whether this client is permitted to read the given entities."""
        return any(restriction.permits_read(index, document, field)
                   for role in self.roles
                   for restriction in role.restrictions)

    def can_write(self, index, document=None, field=None):
        """Return whether this client is permitted to write the given entities."""
        return any(restriction.permits_write(index, document, field)
                   for role in self.roles
                   for restriction in role.restrictions)

    def create_source_filter(self, index, document, source_filter=None):
        """Create and return a source filter based on what this client is permitted or is requesting to access. May
        return a empty filter if the client is not restricted at all and None if the client can't access anything.

        """
        if not self.is_restricted():
            return source_filter or SourceFilter()  # Bail out early if the client is not restricted at all

        includes, excludes = self._collect_restrictions(index, document)
        if includes is None and excludes is None:
            return  # None of the client's restrictions permit access to the given index or document
        elif not includes and not excludes:
            # The client is not restricted and can access every field in the given document
            return source_filter or SourceFilter()

        if not source_filter:
            # The client does not provide a source filter so we can simply return our own
            source_filter = SourceFilter()
            source_filter.includes = includes
            source_filter.excludes = excludes
            return source_filter
        elif source_filter.disabled or source_filter.excludes == ['*']:
            # The client does not want any source fields so we shouldn't provide them either
            return source_filter

        # The client does indeed provide a source filter so let's take a look what exactly it is
        for pattern in source_filter.includes[:]:
            # As long as the client is not further restricted than requested we can keep the pattern as is
            candidates, match_found = [], False
            for permit in includes:
                try:
                    if pattern_compare(permit, pattern) < 0:
                        candidates.append(permit)  # permit is more restrictive than pattern
                    else:
                        break  # permit is equally or less restrictive than pattern
                except ValueError:
                    pass
                else:
                    match_found = True
            else:
                source_filter.includes.remove(pattern)
                if match_found:
                    # In case there is not even a single compatible restriction, just remove it without substitution
                    # as this means what the client requests is not permitted and cannot be alternatively fulfilled
                    source_filter.includes.extend(candidates)

        if not source_filter.includes:
            return  # Nothing what the client requested remained

        source_filter.excludes.extend(excludes)
        return source_filter

    def _collect_restrictions(self, index=None, document=None):
        """Collect and return the includes and excludes from all restrictions which cover the given context.
        The return value is a tuple of two lists or None two times, if no restriction covers the context.

        In case of overlapping rules, only those that give the client the broadest access are returned.
        """
        includes, excludes, restriction_found = {}, {}, False
        for i, restriction in enumerate(rr for r in self.roles for rr in r.restrictions):
            if index is None:
                restriction_found = True
                excludes[i] = restriction.index_excludes
                for pattern in restriction.index_includes:
                    includes.setdefault(pattern, []).append(i)
            elif document is None:
                if restriction.permits_read(index):
                    restriction_found = True
                    excludes[i] = restriction.document_excludes
                    for pattern in restriction.document_includes:
                        includes.setdefault(pattern, []).append(i)
            elif restriction.permits_read(index, document):
                restriction_found = True
                excludes[i] = restriction.field_excludes
                for pattern in restriction.field_includes:
                    includes.setdefault(pattern, []).append(i)

        if not restriction_found:
            return None, None

        # Remove the most restrictive includes
        negligible = []
        for pattern in includes.keys():
            superior = reduce(lambda a, b: a if pattern_compare(a, b, 1) > 0 else b,
                              includes.iterkeys(), pattern)
            if superior != pattern:
                del includes[pattern]
                negligible.append(pattern)

        # Identify which excludes are required based on the remaining includes
        required_excludes = set()
        for groups in includes.itervalues():
            if len(groups) == 1:
                candidates = excludes[groups[0]]
            else:
                candidates = []
                available_excludes = set(p for group in groups for p in excludes[group])
                for pattern in available_excludes:
                    # If there are excludes from different restrictions, use the least restrictive ones
                    inferior = reduce(lambda a, b: a if pattern_compare(a, b, -1) < 0 else b,
                                      available_excludes, pattern)
                    if inferior == pattern:
                        candidates.append(pattern)

            # Just because we've removed the most restrictive includes doesn't mean that the client
            # has no access to the entities covered by them. So let's try to neutralize some excludes
            #
            # TODO: This is in fact true, BUT the include that neutralizes another include's exclude
            #       may have excludes as well, which may then replace the exclude just neutralized.
            #       If you get what I mean, spin this a bit further and you'll realize that this is
            #       recursive as long as an exclude can be neutralized. That's why it's commented out
            #
            #       Example: r1 (a/b/c*,-cd*), r2 (a/b/cd*,-cde*)
            #                - c* overlaps with cd*, so cd* is ignored
            #                - Because c* is used, -cd* is registered but not -cde*
            #                - cd* neutralizes -cd*, but is linked with -cde*
            #                The final result should therefore be: a/b/c*,-cde*
            #
            # required_excludes.update(
            #     filter(lambda p1: not any(pattern_compare(p2, p1, -1) >= 0 for p2 in negligible), candidates))
            required_excludes.update(candidates)

        return includes.keys(), list(required_excludes)


class RestrictionError(AuthorizationError):
    """Raised by class Restriction in case of an error."""
    pass


class Restriction(object):
    """Restriction object that represents a configured client restriction."""

    def __init__(self, restriction):
        self._parsed = False
        self._read_only = None
        self._index_patterns = []
        self._index_includes = []
        self._index_excludes = []
        self._type_patterns = []
        self._type_includes = []
        self._type_excludes = []
        self._field_patterns = []
        self._field_includes = []
        self._field_excludes = []

        self.raw_restriction = restriction

    @property
    def field_includes(self):
        return self._field_patterns[:]

    @property
    def field_excludes(self):
        if not self._field_includes:
            return self._field_excludes[:]

        excludes = []
        for exclude in self._field_excludes:
            if not any(pattern_compare(include, exclude, 0) < 0 for include in self._field_includes):
                excludes.append(exclude)

        return excludes

    def __str__(self):
        return self.raw_restriction

    def _parse_restriction(self):
        if self._parsed:
            return

        parts = self.raw_restriction.split('/')
        if not 1 < len(parts) <= 4:
            raise RestrictionError('Invalid restriction "{0}"'.format(self.raw_restriction))

        for index_pattern in (v.strip() for v in parts[1].split(',')):
            if index_pattern.startswith('-'):
                self._index_excludes.append(index_pattern[1:])
            elif index_pattern.startswith('+'):
                self._index_includes.append(index_pattern[1:])
            else:
                self._index_patterns.append(index_pattern)

        if not self._index_patterns:
            raise RestrictionError(
                'Restriction "{0}" does not provide any index patterns'.format(self.raw_restriction))

        if len(parts) > 2:
            for type_pattern in (v.strip() for v in parts[2].split(',')):
                if type_pattern.startswith('-'):
                    self._type_excludes.append(type_pattern[1:])
                elif type_pattern.startswith('+'):
                    self._type_includes.append(type_pattern[1:])
                else:
                    self._type_patterns.append(type_pattern)

            if not self._type_patterns:
                raise RestrictionError(
                    'Restriction "{0}" does not provide any document type patterns'.format(self.raw_restriction))

        if len(parts) > 3:
            for field_pattern in (v.strip() for v in parts[3].split(',')):
                if field_pattern.startswith('-'):
                    self._field_excludes.append(field_pattern[1:])
                elif field_pattern.startswith('+'):
                    self._field_includes.append(field_pattern[1:])
                else:
                    self._field_patterns.append(field_pattern)

            if not self._field_patterns:
                raise RestrictionError(
                    'Restriction "{0}" does not provide any document field patterns'.format(self.raw_restriction))

        self._read_only = parts[0] == 'read'
        self._parsed = True

    def _apply_restriction(self, subject, patterns, includes, excludes):
        if not any(pattern_match(pattern, subject) for pattern in patterns):
            return False

        if not any(pattern_match(pattern, subject) for pattern in excludes):
            return True

        return any(pattern_match(pattern, subject) for pattern in includes)

    def _check_permission(self, index, document, field):
        if field is not None and not self._field_patterns or document is not None and not self._type_patterns:
            # If it's a document or field request and this restriction doesn't cover those access must be denied
            return False

        if not self._apply_restriction(index, self._index_patterns, self._index_includes, self._index_excludes):
            return False
        elif document is None:
            return True

        if not self._apply_restriction(document, self._type_patterns, self._type_includes, self._type_excludes):
            return False
        elif field is None:
            return True

        return self._apply_restriction(field, self._field_patterns, self._field_includes, self._field_excludes)

    def permits_read(self, index, document=None, field=None):
        """Return whether read access to the given entities is permitted."""
        self._parse_restriction()
        return self._check_permission(index, document, field)

    def permits_write(self, index, document=None, field=None):
        """Return whether write access to the given entities is permitted."""
        self._parse_restriction()
        if self._read_only:
            return False

        return self._check_permission(index, document, field)


class LdapBackend(object):
    """Base class for all LDAP related backends.

    It provides connection handling and basic search functionality.
    All connection related operations are thread-safe.
    """

    def __init__(self, name, get_option):
        self.__local = threading.local()

        self.name = name
        self.url = get_option('url')
        self.bind_dn = get_option('bind_dn')
        self.bind_pw = get_option('bind_pw')
        self.root_dn = get_option('root_dn')

    @property
    def _local(self):
        try:
            self.__local.initialized
        except AttributeError:
            self.__local.bound = False
            self.__local.connection = None
            self.__local.initialized = True

        return self.__local

    @property
    def connection(self):
        """Return the connection to the LDAP server.
        Initializes the connection lazily if necessary."""
        if self._local.connection is None:
            self._local.connection = ldap.initialize(self.url)

        return self._local.connection

    def bind(self, dn=None, password=None):
        """Send a simple bind request with the given DN and password to the LDAP server.
        If neither of those is given, the configured bind_dn and bind_pw will be used."""
        if not self._local.bound:
            if dn is None and password is None:
                dn, password = self.bind_dn, self.bind_pw

            if dn is not None and password is not None:
                self.connection.simple_bind_s(dn, password)
                self._local.bound = True

    def unbind(self):
        """Send a unbind request to the LDAP server and close the connection."""
        if self._local.bound:
            self.connection.unbind()
            self._local.bound = False

        self._local.connection = None

    def search(self, base_dn, search_filter, attributes=None):
        """Send a search request to the LDAP server and return the result.

        The given filter must be a shallow dictionary and is sent as AND filter. You may pass a list of attributes
        you want to retrieve or an empty list to return none, otherwise all attributes are retrieved."""

        if len(search_filter) > 1:
            search_string = '(&(' + ')('.join('{0}={1}'.format(k, v) for k, v in search_filter.iteritems()) + '))'
        elif search_filter:
            search_string = '({0}={1})'.format(*search_filter.items()[0])
        else:
            search_string = '(objectClass=*)'

        attrsonly = 0
        if attributes is not None and not attributes:
            # This is actually quite dirty as I was not able to find a way to select "nothing". This will now
            # only omit the values of all attributes but the attribute names itself are still transmitted
            attrsonly = 1

        return self.connection.search_s(base_dn, ldap.SCOPE_SUBTREE, search_string, attributes, attrsonly)

    def fetch_dn(self, base_dn, filter):
        """Fetch and return a single DN. Raises either ldap.NO_RESULTS_RETURNED
        if no DN could be found or ldap.LDAPError if multiple DNs were found.

        """
        result = self.search(base_dn, filter, [])
        if not result:
            raise ldap.NO_RESULTS_RETURNED(
                {'desc': 'No DN found with filter {0!r} in base DN {1}'.format(filter, base_dn)})
        elif len(result) > 1:
            raise ldap.LDAPError(
                {'desc': 'Multiple DNs found with filter {0!r} in base DN {1}'.format(filter, base_dn)})

        return result[0][0]


class LdapUserBackend(LdapBackend):
    """LDAP backend class providing user account related operations."""

    def __init__(self, name, get_option):
        super(LdapUserBackend, self).__init__(name, get_option)

        self.user_base_dn = get_option('user_base_dn')
        self.user_object_class = get_option('user_object_class')
        self.user_name_attribute = get_option('user_name_attribute')

    def authenticate(self, client):
        """Authenticate the given client and return whether it succeeded or not."""
        try:
            self.bind()
            user_dn = self.fetch_dn(self.user_base_dn, {'objectClass': self.user_object_class,
                                                        self.user_name_attribute: client.name})
            try:
                self.unbind()
                self.bind(user_dn, client.password)
            except ldap.LDAPError:
                return False
            else:
                return True
        finally:
            self.unbind()


class LdapUsergroupBackend(LdapBackend):
    """LDAP backend class providing usergroup related operations."""

    def __init__(self, name, get_option):
        super(LdapUsergroupBackend, self).__init__(name, get_option)
        self._group_cache = {}
        self._cache_lock = ReadWriteLock()

        self.user_base_dn = get_option('user_base_dn')
        self.user_object_class = get_option('user_object_class')
        self.user_name_attribute = get_option('user_name_attribute')
        self.group_base_dn = get_option('group_base_dn')
        self.group_object_class = get_option('group_object_class')
        self.group_name_attribute = get_option('group_name_attribute')
        self.group_membership_attribute = get_option('group_membership_attribute')

    def clear_cache(self):
        """Clear the internal group membership cache."""
        with self._cache_lock.writeContext:
            self._group_cache.clear()

    @Protector('_cache_lock')
    def get_group_memberships(self, client):
        """Fetch and return all usergroups the given client is a member of."""
        membership_cache = self._group_cache.get(client.name)
        now = time.time()

        if membership_cache is not None and membership_cache['expires'] > now:
            memberships = membership_cache['memberships']
        else:
            with self._cache_lock.writeContext:
                self.bind()
                user_dn = self.fetch_dn(
                    self.user_base_dn, {'objectClass': self.user_object_class, self.user_name_attribute: client.name})
                group_filter = {'objectClass': self.group_object_class, self.group_membership_attribute: user_dn}
                results = self.search(self.group_base_dn, group_filter, [self.group_name_attribute])
                memberships = []
                for result in (r for r in results if self.group_name_attribute in r[1]):
                    memberships.extend(result[1][self.group_name_attribute])
                self._group_cache[client.name] = {
                    'memberships': memberships,
                    'expires': now + CACHE_INVALIDATION_INTERVAL
                }
                self.unbind()

        return memberships


class ElasticsearchRoleBackend(LoggingAware, object):
    """Elasticsearch backend class providing role related operations."""

    def __init__(self, settings):
        self.connection = settings.elasticsearch

    def get_role_memberships(self, client):
        """Fetch and return all roles the given client is a member of."""
        request = ElasticRole.search(client.name, client.groups)
        request.params['size'] = 1000  # If you know how to express "unlimited", feel free to change this!

        response = self.connection.process(request)
        if response is None:
            return []

        response.raise_for_status()
        result = response.json()

        roles = []
        for hit in result.get('hits', {}).get('hits', []):
            try:
                role = ElasticRole.from_search_result(hit)
            except ElasticSearchError as error:
                self.log.warning('Failed to create role from search result. An error occurred: %s', error)
            else:
                role.restrictions = [Restriction(r) for r in role.restrictions]
                roles.append(role)

        return roles
