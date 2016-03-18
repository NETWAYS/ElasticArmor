# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

from elasticarmor.request import *
from elasticarmor.util.elastic import SourceFilter


class IndexApiRequest(ElasticRequest):
    locations = {
        'POST': '/{index}/{document}',
        'PUT': [
            '/{index}/{document}/{entity}',
            '/{index}/{document}/{entity}/_create'
        ]
    }

    @Permission('api/document/index')
    def inspect(self, client):
        pass


class GetApiRequest(ElasticRequest):
    locations = {
        'GET': '/{index}/{document}/{entity}',
        'HEAD': '/{index}/{document}/{entity}'
    }

    @Permission('api/document/get')
    def inspect(self, client):
        source_filter = client.create_source_filter(self.index, self.document, SourceFilter.from_query(self.query))
        if source_filter is None:
            raise PermissionError('You\'re not permitted to access the requested document.')
        elif source_filter:
            self.query.discard('_source', '_source_include', '_source_exclude')
            self.query.update(source_filter.as_query())


class GetSourceApiRequest(ElasticRequest):
    locations = {
        'GET': '/{index}/{document}/{entity}/_source'
    }

    @Permission('api/document/get')
    def inspect(self, client):
        pass


class DeleteApiRequest(ElasticRequest):
    locations = {
        'DELETE': '/{index}/{document}/{entity}'
    }

    @Permission('api/document/delete')
    def inspect(self, client):
        pass


class UpdateApiRequest(ElasticRequest):
    locations = {
        'POST': '/{index}/{document}/{entity}/_update'
    }

    @Permission('api/document/update')
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

    @Permissions('api/bulk', 'api/document/get')
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

    @Permission('api/feature/deprecated')
    def inspect(self, client):
        pass


class TermVectorApiRequest(ElasticRequest):
    locations = {
        'GET': '/{index}/{document}/{entity}/_termvector'
    }

    @Permission('api/document/termVector')
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

    @Permissions('api/bulk', 'api/document/termVector')
    def inspect(self, client):
        pass
