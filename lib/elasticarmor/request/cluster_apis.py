# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

from elasticarmor.request import *


class ClusterHealthApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_cluster/health',
            '/_cluster/health/{indices}'
        ]
    }

    @Permission('api/cluster/health')
    def inspect(self, client):
        pass


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

    @Permission('api/cluster/settings/get')
    def inspect(self, client):
        pass


class UpdateClusterSettingsApiRequest(ElasticRequest):
    locations = {
        'PUT': '/_cluster/settings'
    }

    @Permission('api/cluster/settings/update')
    def inspect(self, client):
        pass


class NodesStatsApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_nodes/stats',
            '/_stats/fielddata',
            '/_nodes/{entities}/stats',
            '/_nodes/stats/{keywords}',
            '/_nodes/{entities}/stats/{keywords}'
        ]
    }

    @Permission('api/cluster/nodes/stats')
    def inspect(self, client):
        pass


class NodesInfoApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_nodes',
            '/_nodes/{entities}',
            '/_nodes/{keywords}',
            '/_nodes/{entities}/{keywords}',
            '/_nodes/{entities}/info/{keywords}'
        ]
    }

    @Permission('api/cluster/nodes/info')
    def inspect(self, client):
        pass


class NodesHotThreadsApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_nodes/hot_threads',
            '/_nodes/{entities}/hot_threads'
        ]
    }

    @Permission('api/cluster/nodes/hotThreads')
    def inspect(self, client):
        pass


class NodesShutdownRequest(ElasticRequest):
    locations = {
        'POST': [
            '/_cluster/nodes/_shutdown',
            '/_cluster/nodes/{entities}/_shutdown'
        ]
    }

    @Permission('api/feature/deprecated')
    def inspect(self, client):
        pass
