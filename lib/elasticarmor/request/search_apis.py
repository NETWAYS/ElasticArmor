# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

from elasticarmor.auth import MultipleIncludesError
from elasticarmor.request import *
from elasticarmor.util.elastic import SourceFilter, FilterString


class SearchApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_search',
            '/{indices}/_search',
            '/{indices}/{documents}/_search'
        ],
        'POST': [
            '/_search',
            '/{indices}/_search',
            '/{indices}/{documents}/_search'
        ]
    }

    def inspect(self, client):
        index_filter, type_filter, source_filter, json = self.inspect_request(
            client, FilterString.from_string(self.get_match('indices', '')),
            FilterString.from_string(self.get_match('documents', '')),
            SourceFilter.from_query(self.query), self.json)

        if not self.query.is_false('explain'):
            for index in index_filter.iter_patterns():
                if type_filter:
                    for document_type in type_filter.iter_patterns():
                        if not client.can('api/search/explain', str(index), str(document_type)):
                            raise PermissionError(
                                'You are not permitted to access scoring explanations of the given indices or types.')
                elif not client.can('api/search/explain', str(index)):
                    raise PermissionError('You are not permitted to access scoring explanations of the given indices.')

            if not index_filter and not client.can('api/search/explain'):
                raise PermissionError('You are not permitted to access scoring explanations.')

        if index_filter and type_filter and self.query.get('fields'):
            fields = filter(None, (field.strip() for v in self.query['fields'] for field in v.split(',')))
            forbidden_fields = []
            for index in index_filter.iter_patterns():
                for document_type in type_filter.iter_patterns():
                    for field in fields:
                        if not client.can('api/documents/get', str(index), str(document_type), field):
                            forbidden_fields.append(field)

            if forbidden_fields:
                raise PermissionError('You are not permitted to access the following fields: {0}'
                                      ''.format(', '.join(forbidden_fields)))

        if index_filter:
            if type_filter:
                self.path = '/{0}/{1}/_search'.format(index_filter, type_filter)
            else:
                self.path = '/{0}/_search'.format(index_filter)

        if source_filter:
            self.query.discard('_source', '_source_include', '_source_exclude')
            self.query.update(source_filter.as_query())

        if json is not None:
            self.body = self.json_encode(json)

    @staticmethod
    def inspect_request(client, requested_indices, requested_types, requested_source, json=None):
        restricted_types = client.is_restricted('types')

        try:
            index_filter = client.create_filter_string('api/search/documents', requested_indices,
                                                       single=restricted_types)
        except MultipleIncludesError as error:
            raise PermissionError(
                'You are restricted to specific types or fields. To use the search api, please pick'
                ' a single index from the following list: {0}'.format(', '.join(error.includes)))
        else:
            if index_filter is None:
                raise PermissionError('You are not permitted to search for documents in the given indices.')

        if restricted_types:
            restricted_fields = client.is_restricted('fields')
            requested_index = index_filter.combined[0] if index_filter.combined else index_filter[0]

            try:
                type_filter = client.create_filter_string('api/search/documents', requested_types,
                                                          str(requested_index), restricted_fields)
            except MultipleIncludesError as error:
                raise PermissionError(
                    'You are restricted to specific fields. To use the search api, please pick a'
                    ' single type from the following list: {0}'.format(', '.join(error.includes)))
            else:
                if type_filter is None:
                    raise PermissionError('You are not permitted to search for documents of the given types.')

            if restricted_fields:
                requested_type = type_filter.combined[0] if type_filter.combined else type_filter[0]
                source_filter = client.create_source_filter('api/documents/get', str(requested_index),
                                                            str(requested_type), requested_source)
                if source_filter is None:
                    raise PermissionError('You are not permitted to access the requested document and/or fields.')
            else:
                source_filter = requested_source
        else:
            type_filter = requested_types
            source_filter = requested_source

        return index_filter, type_filter, source_filter, None


class SearchTemplateApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_search/template',
            '/_search/template/{identifier}'
        ],
        'POST': [
            '/_search/template',
            '/_search/template/{identifier}'
        ],
        'DELETE': '/_search/template/{identifier}'
    }

    @Permission('api/search/templates')
    def inspect(self, client):
        pass


class SearchShardsApiRequest(ElasticRequest):
    locations = {
        'GET': '/{indices}/_search_shards',
        'POST': '/{indices}/_search_shards'
    }

    @Permission('api/search/shards')
    def inspect(self, client):
        pass


class SuggestApiRequest(ElasticRequest):
    locations = {
        'GET': '/_suggest',
        'POST': '/_suggest'
    }

    @Permission('api/search/suggest')
    def inspect(self, client):
        pass


class MultiSearchApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_msearch',
            '/{index}/_msearch',
            '/{index}/{document}/_msearch'
        ],
        'POST': [
            '/_msearch',
            '/{index}/_msearch',
            '/{index}/{document}/_msearch'
        ]
    }

    @Permissions('api/bulk', 'api/search/documents')
    def inspect(self, client):
        pass


class CountApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_count',
            '/{indices}/_count',
            '/{indices}/{documents}/_count'
        ],
        'POST': [
            '/_count',
            '/{indices}/_count',
            '/{indices}/{documents}/_count'
        ]
    }

    @Permission('api/search/documents')
    def inspect(self, client):
        pass


class SearchExistsApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_search/exists',
            '/{indices}/_search/exists',
            '/{indices}/{documents}/_search/exists'
        ],
        'POST': [
            '/_search/exists',
            '/{indices}/_search/exists',
            '/{indices}/{documents}/_search/exists'
        ]
    }

    @Permission('api/search/documents')
    def inspect(self, client):
        pass


class ValidateApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_validate/query',
            '/{indices}/_validate/query',
            '/{indices}/{documents}/_validate/query'
        ],
        'POST': [
            '/_validate/query',
            '/{indices}/_validate/query',
            '/{indices}/{documents}/_validate/query',
            '/.kibana/__kibanaQueryValidator/_validate/query'
        ]
    }

    @Permission('api/search/documents')
    def inspect(self, client):
        pass


class ExplainApiRequest(ElasticRequest):
    locations = {
        'GET': '/{index}/{document}/{identifier}/_explain',
        'POST': '/{index}/{document}/{identifier}/_explain'
    }

    @Permission('api/search/explain')
    def inspect(self, client):
        pass


class PercolateApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/{index}/{document}/_percolate',
            '/{index}/{document}/{identifier}/_percolate'
        ],
        'POST': [
            '/{index}/{document}/_percolate',
            '/{index}/{document}/{identifier}/_percolate'
        ]
    }

    @Permission('api/search/percolate')
    def inspect(self, client):
        pass


class MultiPercolateApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_mpercolate',
            '/{index}/_mpercolate',
            '/{index}/{document}/_mpercolate'
        ],
        'POST': [
            '/_mpercolate',
            '/{index}/_mpercolate',
            '/{index}/{document}/_mpercolate'
        ]
    }

    @Permissions('api/bulk', 'api/search/percolate')
    def inspect(self, client):
        pass


class MoreLikeThisApiRequest(ElasticRequest):
    locations = {
        'GET': '/{index}/{document}/{identifier}/_mlt'
    }

    @Permissions('api/feature/deprecated', 'api/search/moreLikeThis')
    def inspect(self, client):
        pass


class FieldStatsApiRequest(ElasticRequest):
    locations = {
        'GET': '/{indices}/_field_stats'
    }

    @Permission('api/search/fieldStats')
    def inspect(self, client):
        pass
