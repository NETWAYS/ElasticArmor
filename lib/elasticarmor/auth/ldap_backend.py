# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import time
import threading

import ldap

from elasticarmor.util.rwlock import ReadWriteLock, Protector

__all__ = ['LdapBackend', 'LdapUserBackend', 'LdapUsergroupBackend']

CACHE_INVALIDATION_INTERVAL = 900  # Seconds


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
        Initializes the connection lazily if necessary.

        """
        if self._local.connection is None:
            self._local.connection = ldap.initialize(self.url)

        return self._local.connection

    def bind(self, dn=None, password=None):
        """Send a simple bind request with the given DN and password to the LDAP server.
        If neither of those is given, the configured bind_dn and bind_pw will be used.

        """
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
        you want to retrieve or an empty list to return none, otherwise all attributes are retrieved.

        """
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
