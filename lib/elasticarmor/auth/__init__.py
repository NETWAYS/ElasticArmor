# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import socket

import requests
from ldap import LDAPError

from elasticarmor.util import format_ldap_error, format_elasticsearch_error, pattern_compare
from elasticarmor.util.elastic import SourceFilter, FilterString
from elasticarmor.util.mixins import LoggingAware

__all__ = ['AuthorizationError', 'Auth', 'MultipleIncludesError', 'Client']


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
                    except LDAPError as error:
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
                except LDAPError as error:
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
                               client, ', '.join(r.id for r in client.roles) or 'None')


class MultipleIncludesError(AuthorizationError):
    """Raised by Client.create_filter_string() if more includes than expected were found.

    The includes that were found are available as instance attribute.
    """

    def __init__(self, includes):
        super(MultipleIncludesError, self).__init__('Multiple includes found')
        self.includes = [str(include) for include in includes]


class Client(LoggingAware, object):
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
        That's either the name, username or the address and port concatenated with a colon.

        """
        if self.name is not None:
            return self.name

        if self.username is not None:
            return self.username

        return '%s:%u' % (self.address, self.port)

    @property
    def restricted_scope(self):
        """The deepest scope within this client is restricted.
        That's either None, 'indices', 'types' or 'fields'.

        """
        try:
            return self._restricted_scope
        except AttributeError:
            scope = None
            for role in self.roles:
                if 'fields' in role.privileges:
                    scope = 'fields'
                    break
                elif 'types' in role.privileges:
                    scope = 'types'
                elif scope is None and 'indices' in role.privileges:
                    scope = 'indices'

            self._restricted_scope = scope
            return self._restricted_scope

    def is_restricted(self, scope='indices'):
        """Return whether this client is restricted within the given scope.
        Valid scopes are 'indices', 'types' and 'fields'.

        """
        if self.restricted_scope == scope:
            return True
        elif scope == 'fields':
            return False

        if scope == 'indices':
            return self.restricted_scope is not None
        elif scope == 'types':
            return self.restricted_scope is not None and self.restricted_scope != 'indices'

        raise AssertionError('Invalid scope "{0}" given'.format(scope))

    def can(self, permission, index=None, document_type=None, field=None):
        """Return whether this client has the given permission in the given context."""
        # TODO: Find a nice way to support both strings AND pattern objects!
        assert index is None or isinstance(index, basestring), 'You are required to pass strings, yet'
        assert document_type is None or isinstance(document_type, basestring), 'You are required to pass strings, yet'
        assert field is None or isinstance(field, basestring), 'You are required to pass strings, yet'
        return any(role.permits(permission, index, document_type, field) for role in self.roles)

    def create_filter_string(self, permission, filter_string=None, index=None, single=False):
        """Create and return a filter string based on what this client is permitted or is requesting to access.
        May return a empty filter if the client is not restricted at all and None if the client can't access
        anything. Raises MultipleIncludesError if single is True and multiple includes were found.

        """
        if not self.is_restricted('indices' if index is None else 'types'):
            # Bail out early if the client is not restricted at all
            return (filter_string or FilterString()) if self.can(permission, index) else None

        filters = self._collect_filters(permission, index)
        if not filters:
            return  # None of the client's restrictions permit access to any index or any document type

        prepared_filter_string = FilterString()
        for include, excludes in filters.iteritems():
            prepared_filter_string.append_include(include)
            for exclude in excludes:
                prepared_filter_string.append_exclude(exclude)

        if filter_string:
            # In case the client provides a filter it may be required to adjust
            # it a little. We'd like to be smart after all, don't we? ;)
            if not filter_string.combine(prepared_filter_string):
                return  # Nothing what the client requested remained

            if single and len(filter_string.combined) > 1:
                # Although the client already provides a filter it does still consist of multiple restrictions
                raise MultipleIncludesError(filter_string.combined)
        elif single and len(filters) > 1:
            # We can obviously only provide multiple filters and since it would be unsafe
            # to make an assumption on what filter to return, we'll refuse to return one
            raise MultipleIncludesError(filters.keys())
        else:
            # The client does not provide a source filter so we can simply return our own
            filter_string = prepared_filter_string

        return filter_string

    def create_source_filter(self, permission, index, document_type, source_filter=None):
        """Create and return a source filter based on what this client is permitted or is requesting to access. May
        return a empty filter if the client is not restricted at all and None if the client can't access anything.

        """
        if not self.is_restricted('fields'):
            # Bail out early if the client is not restricted at all
            return (source_filter or SourceFilter()) if self.can(permission, index, document_type) else None

        filters = self._collect_filters(permission, index, document_type)
        if not filters:
            return  # None of the client's restrictions permit access to the given index or document type

        prepared_source_filter = SourceFilter()
        for include, excludes in filters.iteritems():
            prepared_source_filter.includes.append(include)
            prepared_source_filter.excludes.extend(excludes)

        if not source_filter:
            # The client does not provide a source filter so we can simply return our own
            return prepared_source_filter
        elif source_filter.disabled or source_filter.excludes == ['*']:
            # The client does not want any source fields so we shouldn't provide them either
            return source_filter

        # The client does indeed provide a source filter so let's try to be smart here as well :P
        if not source_filter.combine(prepared_source_filter):
            return  # Nothing what the client requested remained

        return source_filter

    def _collect_filters(self, permission, index=None, document_type=None):
        """Collect and return the filters for the given context which grant the given permission.
        In case of overlapping filters, only those that give the client the broadest access are
        returned.

        """
        filters = {}
        for role in self.roles:
            for restriction in role.get_restrictions(permission, index, document_type):
                for include in restriction.includes:
                    filters.setdefault(include, []).extend(e for e in restriction.excludes)

        # Remove the most restrictive filters
        removed_filters = {}
        for include in filters.keys():
            superior = reduce(lambda a, b: b if b > a else a, filters.iterkeys(), include)
            if include is not superior:
                removed_filters[include] = filters[include]
                del filters[include]

        # Reduce the amount of possible excludes so that only the least restrictive ones remain
        for excludes in (excludes for excludes in filters.itervalues() if len(excludes) > 1):
            # Just because we've removed the most restrictive filters doesn't mean that the client has
            # no access to the entities covered by them. So let's try to neutralize some excludes
            #
            # TODO: This is in fact true, BUT the filter that neutralizes another filter's exclude
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
            # kept_excludes = [e for e in excludes if not any(p is not e and p <= e for p in excludes)]
            # excludes[:] = filter(lambda e: not any(p >= e for p in removed_filters), kept_excludes)
            excludes[:] = [e for e in excludes if not any(p is not e and p <= e for p in excludes)]

        return filters
