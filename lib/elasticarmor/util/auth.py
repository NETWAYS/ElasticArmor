# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import time
import threading

import ldap

from elasticarmor.util.rwlock import ReadWriteLock, Protector

__all__ = ['Client', 'LdapBackend', 'LdapUserBackend', 'LdapUsergroupBackend']

CACHE_INVALIDATION_INTERVAL = 900  # Seconds


class Client(object):
    """An object representing a client who is sending a request."""

    def __init__(self, address, port):
        self.address = address
        self.port = port

        self.username = None
        self.password = None
        self.groups = None

    def is_authenticated(self):
        """Return whether this client authenticated itself by providing a username and password."""
        return self.username is not None and self.password is not None

    def __str__(self):
        """Return a human readable string representation for this client.
        That's either the username or the address and port concatenated with a colon."""
        if self.username is not None:
            return self.username

        return '%s:%u' % (self.address, self.port)


class LdapBackend(object):
    """Base class for all LDAP related backends.

    It provides connection handling and basic search functionality.
    All connection related operations are thread-safe.
    """

    def __init__(self, settings):
        self.__local = threading.local()

        self.url = settings.ldap_url
        self.bind_dn = settings.ldap_bind_dn
        self.bind_pw = settings.ldap_bind_pw
        self.root_dn = settings.ldap_root_dn

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


class LdapUserBackend(LdapBackend):
    """LDAP backend class providing user account related operations."""

    def __init__(self, settings):
        super(LdapUserBackend, self).__init__(settings)

        self.user_base_dn = settings.ldap_user_base_dn
        self.user_object_class = settings.ldap_user_object_class
        self.user_name_attribute = settings.ldap_user_name_attribute

    def fetch_user_dn(self, username):
        """Fetch and return the DN of the given username.
        Raises either ldap.NO_RESULTS_RETURNED if no DN could be found or ldap.LDAPError if multiple DNs were found."""
        user_filter = {'objectClass': self.user_object_class, self.user_name_attribute: username}
        result = self.search(self.user_base_dn, user_filter, [])
        if not result:
            raise ldap.NO_RESULTS_RETURNED({'desc': 'No DN found for user {0}'.format(username)})
        elif len(result) > 1:
            raise ldap.LDAPError({'desc': 'Multiple DNs found for user {0}'.format(username)})

        return result[0][0]


class LdapUsergroupBackend(LdapUserBackend):
    """LDAP backend class providing usergroup related operations."""

    def __init__(self, settings):
        super(LdapUsergroupBackend, self).__init__(settings)
        self._group_cache = {}
        self._cache_lock = ReadWriteLock()

        self.group_base_dn = settings.ldap_group_base_dn
        self.group_object_class = settings.ldap_group_object_class
        self.group_name_attribute = settings.ldap_group_name_attribute
        self.group_membership_attribute = settings.ldap_group_membership_attribute

    @Protector('_cache_lock')
    def get_group_memberships(self, username):
        """Fetch and return all usergroups the user identified by the given username is a member of."""
        membership_cache = self._group_cache.get(username)
        now = time.time()

        if membership_cache is not None and membership_cache['expires'] > now:
            memberships = membership_cache['memberships']
        else:
            with self._cache_lock.writeContext:
                self.bind()
                group_filter = {'objectClass': self.group_object_class,
                                self.group_membership_attribute: self.fetch_user_dn(username)}
                results = self.search(self.group_base_dn, group_filter, [self.group_name_attribute])
                memberships = []
                for result in (r for r in results if self.group_name_attribute in r[1]):
                    memberships.extend(result[1][self.group_name_attribute])
                self._group_cache[username] = {
                    'memberships': memberships,
                    'expires': now + CACHE_INVALIDATION_INTERVAL
                }
                self.unbind()

        return memberships
