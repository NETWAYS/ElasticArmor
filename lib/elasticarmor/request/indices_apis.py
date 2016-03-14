# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

from elasticarmor.request import *


class CreateIndexApiRequest(ElasticRequest):
    locations = {
        'PUT': '/{index}'
    }

    @Permission('api/indices/create')
    def inspect(self, client):
        pass


class DeleteIndexApiRequest(ElasticRequest):
    locations = {
        'DELETE': '/{indices}'
    }

    @Permission('api/indices/delete')
    def inspect(self, client):
        pass


class GetIndexApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/{indices}',
            '/{indices}/{keywords}'
        ]
    }

    @Permission('api/indices/get')
    def inspect(self, client):
        pass


class OpenIndexApiRequest(ElasticRequest):
    locations = {
        'POST': '/{indices}/_open'
    }

    @Permission('api/indices/open')
    def inspect(self, client):
        pass


class CloseIndexApiRequest(ElasticRequest):
    locations = {
        'POST': '/{indices}/_close'
    }

    @Permission('api/indices/close')
    def inspect(self, client):
        pass


class CreateMappingApiRequest(ElasticRequest):
    locations = {
        'PUT': '/{indices}/_mapping{s}/{document}'
    }

    @Permission('api/indices/mapping/create')
    def inspect(self, client):
        pass


class GetMappingApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_mapping{s}',
            '/{indices}/_mapping{s}',
            '/_mapping{s}/{documents}',
            '/{indices}/_mapping{s}/{documents}'
        ],
        'HEAD': '/{indices}/{documents}'
    }

    @Permission('api/indices/mapping/get')
    def inspect(self, client):
        pass


class GetFieldMappingApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/{indices}/_mapping{s}/field/{entities}',
            '/{indices}/{documents}/_mapping{s}/field/{entities}',
            '/{indices}/_mapping{s}/{documents}/field/{entities}'
        ]
    }

    @Permission('api/indices/mapping/get')
    def inspect(self, client):
        pass


class DeleteMappingApiRequest(ElasticRequest):
    locations = {
        'DELETE': [
            '/{indices}/_mapping{s}',
            '/{indices}/{documents}/_mapping{s}',
            '/{indices}/_mapping{s}/{documents}'
        ]
    }

    @Permission('api/indices/mapping/delete')
    def inspect(self, client):
        pass


class CreateAliasApiRequest(ElasticRequest):
    locations = {
        'POST': '/_aliases',
        'PUT': '/{indices}/_alias{es}/{entity}'
    }

    @Permission('api/indices/alias/create')
    def inspect(self, client):
        pass


class DeleteAliasApiRequest(ElasticRequest):
    locations = {
        'DELETE': '/{indices}/_alias{es}/{entities}'
    }

    @Permission('api/indices/alias/delete')
    def inspect(self, client):
        pass


class GetAliasApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_alias',
            '/_alias/{entity}',
            '/{indices}/_alias',
            '/{indices}/_alias/{entity}'
        ]
    }

    @Permission('api/indices/alias/get')
    def inspect(self, client):
        pass


class UpdateIndexSettingsApiRequest(ElasticRequest):
    locations = {
        'PUT': [
            '/_settings',
            '/{indices}/_settings'
        ]
    }

    @Permission('api/indices/settings/update')
    def inspect(self, client):
        pass


class GetIndexSettingsApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_settings',
            '/{indices}/_settings'
        ]
    }

    @Permission('api/indices/settings/get')
    def inspect(self, client):
        pass


class AnalyzeApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_analyze',
            '/{index}/_analyze'
        ],
        'POST': [
            '/_analyze',
            '/{index}/_analyze'
        ]
    }

    @Permission('api/indices/analyze')
    def inspect(self, client):
        pass


class CreateIndexTemplateApiRequest(ElasticRequest):
    locations = {
        'PUT': '/_template/{entity}'
    }

    @Permission('api/indices/template/create')
    def inspect(self, client):
        pass


class DeleteIndexTemplateApiRequest(ElasticRequest):
    locations = {
        'DELETE': '/_template/{entity}'
    }

    @Permission('api/indices/template/delete')
    def inspect(self, client):
        pass


class GetIndexTemplateApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_template',
            '/_template/{entities}'
        ]
    }

    @Permission('api/indices/template/get')
    def inspect(self, client):
        pass


class CreateIndexWarmerApiRequest(ElasticRequest):
    locations = {
        'PUT': [
            '/_warmer{s}/{entity}',
            '/{indices}/_warmer{s}/{entity}',
            '/{indices}/{documents}/_warmer{s}/{entity}'
        ]
    }

    @Permission('api/indices/warmer/create')
    def inspect(self, client):
        pass


class DeleteIndexWarmerApiRequest(ElasticRequest):
    locations = {
        'DELETE': '/{indices}/_warmer{s}/{entities}'
    }

    @Permission('api/indices/warmer/delete')
    def inspect(self, client):
        pass


class GetIndexWarmerApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_warmer{s}/{entities}',
            '/{indices}/_warmer{s}/{entities}'
        ]
    }

    @Permission('api/indices/warmer/get')
    def inspect(self, client):
        pass


class IndexStatsApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_stats',
            '/{indices}/_stats'
        ]
    }

    @Permission('api/indices/stats')
    def inspect(self, client):
        pass


class IndexSegmentsApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_segments',
            '/{indices}/_segments'
        ]
    }

    @Permission('api/indices/segments')
    def inspect(self, client):
        pass


class IndexRecoveryApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_recovery',
            '/{indices}/_recovery'
        ]
    }

    @Permission('api/indices/recovery')
    def inspect(self, client):
        pass


class IndexCacheApiRequest(ElasticRequest):
    locations = {
        'POST': [
            '/_cache/clear',
            '/{indices}/_cache/clear'
        ]
    }

    @Permission('api/indices/cache/clear')
    def inspect(self, client):
        pass


class IndexFlushApiRequest(ElasticRequest):
    locations = {
        'POST': [
            '/_flush',
            '/_flush/synced',
            '/{indices}/_flush',
            '/{indices}/_flush/synced'
        ]
    }

    @Permission('api/indices/flush')
    def inspect(self, client):
        pass


class IndexRefreshApiRequest(ElasticRequest):
    locations = {
        'POST': [
            '/_refresh',
            '/{indices}/_refresh'
        ]
    }

    @Permission('api/indices/refresh')
    def inspect(self, client):
        pass


class IndexOptimizeApiRequest(ElasticRequest):
    locations = {
        'POST': [
            '/_optimize',
            '/{indices}/_optimize'
        ]
    }

    @Permission('api/indices/optimize')
    def inspect(self, client):
        pass


class IndexUpgradeApiRequest(ElasticRequest):
    locations = {
        'GET': '/{index}/_upgrade',
        'POST': '/{index}/_upgrade'
    }

    @Permission('api/indices/upgrade')
    def inspect(self, client):
        pass
