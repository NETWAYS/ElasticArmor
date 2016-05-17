# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import crypt

from elasticarmor.auth.role import Role
from elasticarmor.util.elastic import ElasticSearchError, ElasticUser
from elasticarmor.util.mixins import LoggingAware

__all__ = ['ElasticsearchRoleBackend']


class ElasticsearchRoleBackend(LoggingAware, object):
    """Elasticsearch backend class providing role related operations."""

    def __init__(self, settings):
        self.connection = settings.elasticsearch

    def get_role_memberships(self, client):
        """Fetch and return all roles the given client is a member of."""
        request = Role.search(client.name, client.groups)
        request.params['size'] = 1000  # If you know how to express "unlimited", feel free to change this!

        response = self.connection.process(request)
        if response is None:
            return []

        response.raise_for_status()
        result = response.json()

        roles = []
        for hit in result.get('hits', {}).get('hits', []):
            try:
                roles.append(Role.from_search_result(hit))
            except ElasticSearchError as error:
                self.log.warning('Failed to create role from search result. An error occurred: %s', error)

        if client.default_role is not None and not any(role.id == client.default_role for role in roles):
            response = self.connection.process(Role.get_source(client.default_role))
            if response is not None and response.ok:
                try:
                    roles.append(Role.from_source(client.default_role, response.json()))
                except ElasticSearchError as error:
                    self.log.warning('Failed to create role from source. An error occurred: %s', error)
            else:
                self.log.warning('Unable to retrieve default role "%s" for client "%s".', client.default_role, client)

        return roles


class ElasticsearchUserBackend(LoggingAware, object):
    """Elasticsearch backend class providing user account related operations."""

    def __init__(self, name, get_option, settings):
        self.connection = settings.elasticsearch
        self.name = name

    def authenticate(self, client):
        """Authenticate the given client and return whether it succeeded or not."""
        response = self.connection.process(ElasticUser.get_source(client.name))
        if response is None:
            return False

        if not response.ok:
            if response.status_code == 404:
                return False

            response.raise_for_status()

        user = ElasticUser.from_source(client.name, response.json())
        return self._compare_hashes(
            self._hash_password(client.password, self._extract_salt(user.password_hash)),
            user.password_hash
        )

    def _hash_password(self, password, salt):
        """Hash the given password with the given salt and return the result."""
        return crypt.crypt(password, '$1$' + salt)

    def _extract_salt(self, password_hash):
        """Extract and return the salt of the given password hash."""
        return password_hash[3:11]

    def _compare_hashes(self, a, b):
        """Return whether the given hashes match."""
        return a == b
