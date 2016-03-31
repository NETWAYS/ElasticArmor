# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

from elasticarmor.request import *
from elasticarmor.util.elastic import FilterString


class ClusterInfoApiRequest(ElasticRequest):
    def is_valid(self):
        return self.path == '/'

    def inspect(self, client):
        pass


class ClusterHealthApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_cluster/health',
            '/_cluster/health/{indices}'
        ]
    }

    def inspect(self, client):
        requested_indices = FilterString.from_string(self.get_match('indices', ''))
        index_filter = client.create_filter_string('api/cluster/health', requested_indices)
        if index_filter is None:
            raise PermissionError('You are not permitted to check the cluster health for the requested indices.')
        elif index_filter:
            self.path = '/_cluster/health/{0}'.format(index_filter)


class ClusterStateApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_cluster/state',
            '/_cluster/state/{keywords}',
            '/_cluster/state/{keywords}/{indices}'
        ]
    }

    @Permission('api/cluster/state')
    def inspect(self, client):
        pass


class ClusterStatsApiRequest(ElasticRequest):
    locations = {
        'GET': '/_cluster/stats'
    }

    @Permission('api/cluster/stats')
    def inspect(self, client):
        pass


class ClusterPendingTasksApiRequest(ElasticRequest):
    locations = {
        'GET': '/_cluster/pending_tasks'
    }

    @Permission('api/cluster/pendingTasks')
    def inspect(self, client):
        pass


class ClusterRerouteApiRequest(ElasticRequest):
    locations = {
        'POST': '/_cluster/reroute'
    }

    @Permission('api/cluster/reroute')
    def inspect(self, client):
        pass


class GetClusterSettingsApiRequest(ElasticRequest):
    locations = {
        'GET': '/_cluster/settings'
    }

    @Permission('api/cluster/get/settings')
    def inspect(self, client):
        pass


class UpdateClusterSettingsApiRequest(ElasticRequest):
    locations = {
        'PUT': '/_cluster/settings'
    }

    @Permission('api/cluster/update/settings')
    def inspect(self, client):
        pass


class NodesStatsApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_nodes/stats',
            '/_stats/fielddata',
            '/_nodes/{identifiers}/stats',
            '/_nodes/stats/{keywords}',
            '/_nodes/{identifiers}/stats/{keywords}'
        ]
    }

    @Permission('api/cluster/nodes/stats')
    def inspect(self, client):
        pass


class NodesInfoApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_nodes',
            '/_nodes/{identifiers}',
            '/_nodes/{keywords}',
            '/_nodes/{identifiers}/{keywords}',
            '/_nodes/{identifiers}/info/{keywords}'
        ]
    }

    @Permission('api/cluster/nodes/info')
    def inspect(self, client):
        pass


class NodesHotThreadsApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_nodes/hot_threads',
            '/_nodes/{identifiers}/hot_threads'
        ]
    }

    @Permission('api/cluster/nodes/hotThreads')
    def inspect(self, client):
        pass


class NodesShutdownRequest(ElasticRequest):
    locations = {
        'POST': [
            '/_cluster/nodes/_shutdown',
            '/_cluster/nodes/{identifiers}/_shutdown'
        ]
    }

    @Permissions('api/feature/deprecated', 'api/cluster/nodes/shutdown')
    def inspect(self, client):
        pass
