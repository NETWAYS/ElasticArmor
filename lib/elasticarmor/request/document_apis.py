# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

from elasticarmor.request import *
from elasticarmor.util.elastic import SourceFilter


class IndexApiRequest(ElasticRequest):
    locations = {
        'POST': '/{index}/{document}',
        'PUT': [
            '/{index}/{document}/{identifier}',
            '/{index}/{document}/{identifier}/_create'
        ]
    }

    @Permission('api/documents/index')
    def inspect(self, client):
        pass


class GetApiRequest(ElasticRequest):
    locations = {
        'GET': '/{index}/{document}/{identifier}',
        'HEAD': '/{index}/{document}/{identifier}'
    }

    def inspect(self, client):
        source_filter = client.create_source_filter('api/documents/get', self.index, self.document,
                                                    SourceFilter.from_query(self.query))
        if source_filter is None:
            raise PermissionError('You are not permitted to access the requested document and/or fields.')
        elif source_filter:
            self.query.discard('_source', '_source_include', '_source_exclude')
            self.query.update(source_filter.as_query())


class GetSourceApiRequest(ElasticRequest):
    locations = {
        'GET': '/{index}/{document}/{identifier}/_source'
    }

    @Permission('api/documents/get')
    def inspect(self, client):
        pass


class DeleteApiRequest(ElasticRequest):
    locations = {
        'DELETE': '/{index}/{document}/{identifier}'
    }

    @Permission('api/documents/delete')
    def inspect(self, client):
        pass


class UpdateApiRequest(ElasticRequest):
    locations = {
        'POST': [
            '/{index}/{document}/{identifier}',
            '/{index}/{document}/{identifier}/_update'
        ]
    }

    @Permission('api/documents/update')
    def inspect(self, client):
        pass


class MultiGetApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_mget',
            '/{index}/_mget',
            '/{index}/{document}/_mget'
        ],
        'POST': [
            '/_mget',
            '/{index}/_mget',
            '/{index}/{document}/_mget'
        ]
    }

    @Permissions('api/bulk', 'api/documents/get')
    def inspect(self, client):
        pass


class BulkApiRequest(ElasticRequest):
    locations = {
        'POST': [
            '/_bulk',
            '/{index}/_bulk',
            '/{index}/{document}/_bulk'
        ]
    }

    @Permission('api/bulk')
    def inspect(self, client):
        pass


class DeleteByQueryApiRequest(ElasticRequest):
    locations = {
        'DELETE': [
            '/_query',
            '/{indices}/_query',
            '/{indices}/{documents}/_query'
        ]
    }

    @Permissions('api/feature/deprecated', 'api/documents/deleteByQuery')
    def inspect(self, client):
        pass


class TermVectorApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/{index}/{document}/_termvector',
            '/{index}/{document}/{identifier}/_termvector'
        ]
    }

    @Permission('api/documents/termVector')
    def inspect(self, client):
        pass


class MultiTermVectorApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_mtermvectors',
            '/{index}/_mtermvectors',
            '/{index}/{document}/_mtermvectors'
        ]
    }

    @Permissions('api/bulk', 'api/documents/termVector')
    def inspect(self, client):
        pass
