# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

from elasticarmor.request import *


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

    @Permission('api/search/documents')
    def inspect(self, client):
        pass


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
