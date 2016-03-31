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

    def inspect(self, client):
        # TODO: Check if it's required to validate a parent's id (Whether the client has access to the parent's type)
        if not client.can('api/documents/index', self.index, self.document):
            raise PermissionError('You are not permitted to index documents of this type in the given index.')
        elif client.has_restriction(self.index, self.document):
            raise PermissionError('You are restricted to specific fields of the given type.'
                                  ' Please use the update api instead.')
        elif not self.query.is_false('refresh') and not client.can('api/indices/refresh', self.index):
            raise PermissionError('You are not permitted to refresh this index.')


class GetApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/{index}/{document}/{identifier}',
            '/{index}/{document}/{identifier}/_source'
        ],
        'HEAD': [
            '/{index}/{document}/{identifier}',
            '/{index}/{document}/{identifier}/_source'
        ]
    }

    def inspect(self, client):
        source_filter = client.create_source_filter('api/documents/get', self.index, self.document,
                                                    SourceFilter.from_query(self.query))
        if source_filter is None:
            raise PermissionError('You are not permitted to access the requested document and/or fields.')
        elif source_filter:
            self.query.discard('_source', '_source_include', '_source_exclude')
            self.query.update(source_filter.as_query())

        if not source_filter.disabled and 'fields' in self.query:
            forbidden_fields = []
            for field in (field.strip() for v in self.query['fields'] for field in v.split(',')):
                if field and not client.can('api/documents/get', self.index, self.document, field):
                    forbidden_fields.append(field)

            if forbidden_fields:
                # The fields parameter is not rewritten since it does not support
                # wildcards and therefore contains only explicit values
                raise PermissionError('You are not permitted to access the following fields: {0}'
                                      ''.format(', '.join(forbidden_fields)))


class DeleteApiRequest(ElasticRequest):
    locations = {
        'DELETE': '/{index}/{document}/{identifier}'
    }

    def inspect(self, client):
        # TODO: Check if it's required to validate a parent's id (Whether the client has access to the parent's type)
        if not client.can('api/documents/delete', self.index, self.document):
            raise PermissionError('You are not permitted to delete documents of this type in the given index.')
        elif client.has_restriction(self.index, self.document):
            raise PermissionError('You are restricted to specific fields of the given type.')
        elif not self.query.is_false('refresh') and not client.can('api/indices/refresh', self.index):
            raise PermissionError('You are not permitted to refresh this index.')


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
