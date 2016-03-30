# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

from elasticarmor.auth.role import Role
from elasticarmor.util.elastic import ElasticSearchError
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

        return roles
