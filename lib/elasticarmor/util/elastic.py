# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import time
import urllib
import threading

import requests

from elasticarmor.util import format_elasticsearch_error
from elasticarmor.util.rwlock import ReadWriteLock
from elasticarmor.util.mixins import LoggingAware

__all__ = ['ElasticSearchError', 'ElasticConnection', 'ElasticObject', 'ElasticRole', 'QueryDslParser',
           'AggregationParser', 'parse_source_filter']

DEFAULT_TIMEOUT = 5  # Seconds
CHECK_REACHABILITY_INTERVAL = 900  # Seconds


class ElasticSearchError(Exception):
    pass


class ElasticConnection(LoggingAware, object):
    """Class for failover handling of multiple Elasticsearch nodes."""
    def __init__(self, nodes):
        self._last_check = None
        self._unreachable_nodes = []
        self._node_priorities = dict((node, index) for index, node in enumerate(nodes))

        self._check_flag = threading.Event()
        self._reachable_nodes_lock = ReadWriteLock()
        self._unreachable_nodes_lock = ReadWriteLock()

        self.nodes = nodes

    @property
    def _reachable_nodes(self):
        """Return a list of all currently available nodes."""
        with self._reachable_nodes_lock.readContext:
            return self.nodes[:]

    def _mark_as_unreachable(self, node):
        """Register the given node as unreachable."""
        with self._reachable_nodes_lock.writeContext:
            self.nodes.remove(node)

        with self._unreachable_nodes_lock.writeContext:
            self._unreachable_nodes.append(node)

    def _is_reachability_check_necessary(self):
        """Return whether it is necessary to check node reachability."""
        return self._unreachable_nodes and (self._last_check is None or
                                            time.time() - self._last_check > CHECK_REACHABILITY_INTERVAL)

    def check_reachability(self):
        """Check all currently unavailable nodes whether they are still unreachable."""
        if not self._is_reachability_check_necessary() or self._check_flag.is_set():
            return  # Checking reachability is either not necessary or another thread is currently doing it

        # Notify any other request thread that we're now checking reachability
        self._check_flag.set()

        # Check if any unreachable nodes are reachable again
        reachable_nodes = []
        with self._unreachable_nodes_lock.writeContext:
            for node in self._unreachable_nodes[:]:
                try:
                    if requests.head(node).raise_for_status():
                        self._unreachable_nodes.remove(node)
                        reachable_nodes.append(node)
                        self.log.debug('Node "%s" is reachable and being made available again.', node)
                except requests.RequestException as error:
                    self.log.debug('Node "%s" is still unreachable. Error: %s',
                                   node, format_elasticsearch_error(error))

        if reachable_nodes:
            # Make the now reachable nodes available again and ensure that the priority order is restored
            with self._reachable_nodes_lock.writeContext:
                self.nodes = sorted(self.nodes.extend(reachable_nodes), key=self._node_priorities.__getitem__)

        self.log.debug('Currently available nodes: %s', ', '.join(self.nodes) if self.nodes else 'None')
        self.log.debug('Currently unavailable nodes: %s',
                       ', '.join(self._unreachable_nodes) if self._unreachable_nodes else 'None')

        # Remember when we've checked reachability the last time and clear the flag
        self._last_check = time.time()
        self._check_flag.clear()

    def process(self, request):
        """Send the given request to Elasticsearch and return its response.
        Returns None if it was not possible to receive a response."""
        try:  # It's either a ElasticRequestHandler, a ElasticRequest ..
            request_path = request.path
        except AttributeError:  # .. or a requests.Request
            request_path = request.url
            encoded_query = urllib.urlencode(request.params, True)
            prepared_request = requests.PreparedRequest()
            prepared_request.prepare_method(request.method)
            prepared_request.prepare_headers(request.headers)
            prepared_request.prepare_body(request.data, request.files, request.json)
        else:
            encoded_query = urllib.urlencode(request.query, True)
            prepared_request = requests.PreparedRequest()
            prepared_request.prepare_method(request.command)
            prepared_request.prepare_headers(request.headers)
            prepared_request.prepare_body(request.body, None)

        if prepared_request.body:
            self.log.debug('Processing Elasticsearch request "%s %s" with body %r...', prepared_request.method,
                           request_path + ('?' + encoded_query if encoded_query else ''), prepared_request.body)
        else:
            self.log.debug('Processing Elasticsearch request "%s %s"...', prepared_request.method,
                           request_path + ('?' + encoded_query if encoded_query else ''))

        first_error = None
        with requests.Session() as session:
            for node in self._reachable_nodes:
                prepared_request.prepare_url(node + request_path, encoded_query)

                try:
                    # TODO: Interpret the timeout= query parameter for Elasticsearch
                    response = session.send(prepared_request, stream=True, timeout=DEFAULT_TIMEOUT)
                except requests.Timeout:
                    self.log.warning('Node "%s" timed out.', node)
                    self._mark_as_unreachable(node)
                except requests.RequestException as error:
                    self.log.warning('Failed to connect to node "%s". An error occurred: %s',
                                     node, format_elasticsearch_error(error))
                    self._mark_as_unreachable(node)
                    if first_error is None:
                        first_error = error
                else:
                    self.log.debug('Got response with status %u from node "%s".', response.status_code, node)
                    return response

        if first_error is not None:
            # Re-raise the exception which occurred first to indicate
            # to the user that we were not able to fetch a response
            raise first_error


class ElasticObject(LoggingAware, object):
    """Base class for all objects stored in our internal Elasticsearch index."""
    index_name = '.elasticarmor'
    document_type = '_all'

    def __init__(self, id):
        self.id = id

    @classmethod
    def request(cls, endpoint=None, **kwargs):
        """Create and return a new request based on the given arguments.

        If argument endpoint is given but no url using the keyword arguments a default url without
        scheme and host of the following form is used: /index/document-type/endpoint"""

        if endpoint is not None and 'url' not in kwargs:
            kwargs['url'] = '/{0}/{1}/{2}'.format(cls.index_name, cls.document_type, endpoint)

        return requests.Request(**kwargs)

    @classmethod
    def from_search_result(cls, result):
        """Create and return a new instance of this class using the given result from a previous search request.

        Raises ElasticSearchError if the given search result is invalid.
        Overwrite this if you need to process non-default search results."""

        # If this is false, it is the developer's fault or it may indicate some incompatibility
        # to the used Elasticsearch version. Anyway, we need to make sure this is a fatal error
        # and truly no one should catch assertion errors.
        assert '_id' in result, 'Document id missing'

        if not result.get('_source'):
            raise ElasticSearchError('Search result with id "{0}" is missing a source document'.format(result['_id']))

        try:
            return cls(result['_id'], **result['_source'])
        except TypeError:
            raise ElasticSearchError('Search result with id "{0}" is missing one or more fields'.format(result['_id']))


class ElasticRole(ElasticObject):
    """ElasticRole object representing a client's role."""
    document_type = 'role'

    def __init__(self, id, name, permissions, restrictions):
        super(ElasticRole, self).__init__(id)
        self.name = name
        self.users = None
        self.groups = None
        self.permissions = permissions
        self.restrictions = restrictions

    @classmethod
    def search(cls, user=None, groups=None):
        """Create and return a new search request to fetch roles the
        given user or one of the given groups is a member of."""
        data = None
        if user or groups:
            conditions = []
            if user:
                conditions.append({'query': {'match': {'users': user}}})

            if groups:
                conditions.append({
                    'bool': {
                        'should': [{'query': {'match': {'groups': group}}} for group in groups]
                    }
                })

            data = {
                'query': {
                    'filtered': {
                        'query': {
                            'match_all': {}
                        },
                        'filter': {
                            'bool': {
                                'should': conditions
                            }
                        }
                    }
                }
            }

        query_params = {
            'filter_path': 'hits.hits._id,hits.hits._source',
            '_source': 'name,permissions,restrictions'
        }

        return cls.request('_search', method='GET', params=query_params, json=data)


# TODO: Be more strict if it's about irrelevant top-level keywords!
class QueryDslParser(object):
    """QueryDslParser object to parse Elasticsearch queries and filters.

    The most common usage is probably as follows:

        parser = QueryDslParser().query(json_body['query'])

    But the parser is not limited to this single entry point.
    Any other public method serves this purpose just as well:

        QueryDslParser().bool_query(json_object['bool'])
        QueryDslParser().and_filter(json_object['and'])

    Once the parser has finished, all collected permissions, indices, documents
    and their fields can be accessed using the respective instance attributes:

        parser.permissions -> ['<permission-name>']
        parser.indices -> ['<index-name>']
        parser.documents -> [('<index-name>' | None, '<document-name>')]
        parser.fields -> [('<index-name>' | None, '<document-name>' | None, '<field-name>')]

    Any occurrence of 'None' indicates that no particular index or document is desired instead of the default ones.
    """

    def __init__(self):
        self.permissions = set()
        self.indices = set()
        self.documents = set()
        self.fields = set()

        self._query_parsers = {
            'query': self.query,
            'match': self.match_query,
            'match_phrase': self.match_query,
            'match_phrase_prefix': self.match_query,
            'multi_match': self.multi_match_query,
            'bool': self.bool_query,
            'boosting': self.boosting_query,
            'common': self.common_query,
            'constant_score': self.constant_score_query,
            'dis_max': self.dis_max_query,
            'filtered': self.filtered_query,
            'fuzzy_like_this': self.fuzzy_like_this_query,
            'flt': self.fuzzy_like_this_query,
            'fuzzy_like_this_field': self.fuzzy_like_this_field_query,
            'flt_field': self.fuzzy_like_this_field_query,
            'function_score': self.function_score_query,
            'fuzzy': self.fuzzy_query,
            'geo_shape': self.geo_shape_query,
            'has_child': self.has_child_query,
            'has_parent': self.has_parent_query,
            'ids': self.ids_query,
            'indices': self.indices_query,
            'match_all': self.match_all_query,
            'more_like_this': self.more_like_this_query,
            'mlt': self.more_like_this_query,
            'nested': self.nested_query,
            'prefix': self.prefix_query,
            'query_string': self.query_string_query,
            'simple_query_string': self.simple_query_string_query,
            'range': self.range_query,
            'regexp': self.regexp_query,
            'span_first': self.span_first_query,
            'span_multi': self.span_multi_query,
            'span_near': self.span_near_query,
            'span_not': self.span_not_query,
            'span_or': self.span_or_query,
            'span_term': self.span_term_query,
            'term': self.term_query,
            'terms': self.terms_query,
            'in': self.terms_query,
            'top_children': self.top_children_query,
            'wildcard': self.wildcard_query,
            'template': self.template_query
        }

        self._filter_parsers = {
            'filter': self.filter,
            'and': self.and_filter,
            'bool': self.bool_filter,
            'exists': self.exists_filter,
            'geo_bounding_box': self.geo_bounding_box_filter,
            'geo_distance': self.geo_distance_filter,
            'geo_distance_range': self.geo_distance_range_filter,
            'geo_polygon': self.geo_polygon_filter,
            'geo_shape': self.geo_shape_filter,
            'geohash_cell': self.geohash_cell_filter,
            'has_child': self.has_child_filter,
            'has_parent': self.has_parent_filter,
            'ids': self.ids_filter,
            'indices': self.indices_filter,
            'limit': self.limit_filter,
            'match_all': self.match_all_filter,
            'missing': self.missing_filter,
            'nested': self.nested_filter,
            'not': self.not_filter,
            'or': self.or_filter,
            'prefix': self.prefix_filter,
            'fquery': self.query_filter,
            'range': self.range_filter,
            'regexp': self.regexp_filter,
            'script': self.script_filter,
            'term': self.term_filter,
            'terms': self.terms_filter,
            'in': self.terms_filter,
            'type': self.type_filter
        }

    def _parse_query(self, name, obj, index=None, document=None):
        """Parse the given query. Raises ElasticSearchError if it is unknown."""
        try:
            self._query_parsers[name](obj, index, document)
        except KeyError:
            raise ElasticSearchError('Unknown query "{0}"'.format(name))

    def _parse_filter(self, name, obj, index=None, document=None):
        """Parse the given filter. Raises ElasticSearchError if it is unknown."""
        try:
            self._filter_parsers[name](obj, index, document)
        except KeyError:
            raise ElasticSearchError('Unknown filter "{0}"'.format(name))

    def _read_object(self, data):
        """Validate and return an object from the given data. Raises ElasticSearchError if the validation fails."""
        try:
            iterator = data.iterkeys()
        except AttributeError:
            raise ElasticSearchError('Invalid JSON object "{0!r}"'.format(data))

        object_name = next(iterator, None)
        if not object_name:
            raise ElasticSearchError('Missing start object in "{0!r}"'.format(data))
        elif next(iterator, None) is not None:
            raise ElasticSearchError('Multiple objects in "{0!r}"'.format(data))
        elif not isinstance(data[object_name], dict):
            raise ElasticSearchError('Invalid start object "{0!r}"'.format(data[object_name]))

        return object_name, data[object_name]

    def _read_field(self, obj, blacklist=None):
        """Identify and return the field name in the given object."""
        return next((k for k in obj.iterkeys() if k[0] != '_' and (not blacklist or k not in blacklist)), None)

    def query(self, obj, index=None, document=None):
        """Recurse into the given query and parse its contents."""
        self._parse_query(*self._read_object(obj), index=index, document=document)

    def match_query(self, obj, index=None, document=None):
        """Parse the given match query. Raises ElasticSearchError in case the query is malformed."""
        field_name = self._read_field(obj)
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in match query "{0!r}"'.format(obj))

    def multi_match_query(self, obj, index=None, document=None):
        """Parse the given multi_match query. Raises ElasticSearchError in case the query is malformed."""
        try:
            fields = obj['fields']
        except KeyError:
            raise ElasticSearchError('Keyword "fields" missing in multi_match query "{0!r}"'.format(obj))

        if not fields:
            raise ElasticSearchError('No fields provided in multi_match query "{0!r}"'.format(obj))

        self.fields.update((index, document, field) for field in fields)

    def bool_query(self, obj, index=None, document=None):
        """Parse the given bool query. Raises ElasticSearchError in case the query is malformed."""
        if 'must' not in obj and 'must_not' not in obj and 'should' not in obj:
            raise ElasticSearchError('No valid keyword given in bool query "{0!r}"'.format(obj))

        for keyword in (kw for kw in ['must', 'must_not', 'should'] if kw in obj):
            if isinstance(obj[keyword], list):
                for query in obj[keyword]:
                    self.query(query, index, document)
            else:
                self.query(obj[keyword], index, document)

    def boosting_query(self, obj, index=None, document=None):
        """Parse the given boosting query. Raises ElasticSearchError in case the query is malformed."""
        if 'positive' not in obj or 'negative' not in obj:
            raise ElasticSearchError(
                'Mandatory keyword "positive" or "negative" missing in boosting query "{0!r}"'.format(obj))

        for keyword in ['positive', 'negative']:
            if isinstance(obj[keyword], list):
                for query in obj[keyword]:
                    self.query(query, index, document)
            else:
                self.query(obj[keyword], index, document)

    def common_query(self, obj, index=None, document=None):
        """Parse the given common query. Raises ElasticSearchError in case the query is malformed."""
        field_name = self._read_field(obj)
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in common query "{0!r}"'.format(obj))

    def constant_score_query(self, obj, index=None, document=None):
        """Parse the given constant_score query. Raises ElasticSearchError in case the query is malformed."""
        if 'query' not in obj and 'filter' not in obj:
            raise ElasticSearchError('No valid keyword given in constant_score query "{0!r}"'.format(obj))

        if 'query' in obj:
            self.query(obj['query'], index, document)
        if 'filter' in obj:
            self.filter(obj['filter'], index, document)

    def dis_max_query(self, obj, index=None, document=None):
        """Parse the given dis_max query. Raises ElasticSearchError in case the query is malformed."""
        try:
            queries = obj['queries']
        except KeyError:
            raise ElasticSearchError('Keyword "queries" missing in dis_max query "{0!r}"'.format(obj))

        if not queries:
            raise ElasticSearchError('No queries provided in dis_max query "{0!r}"'.format(obj))

        for query in queries:
            self.query(query, index, document)

    def filtered_query(self, obj, index=None, document=None):
        """Parse the given filtered query. Raises ElasticSearchError in case the query is malformed."""
        if 'filter' not in obj:
            raise ElasticSearchError('Keyword "filter" missing in filtered query "{0!r}"'.format(obj))

        self.filter(obj['filter'], index, document)
        if 'query' in obj:
            self.query(obj['query'], index, document)

    def fuzzy_like_this_query(self, obj, index=None, document=None):
        """Parse the given fuzzy_like_this query. Raises ElasticSearchError in case the query is malformed."""
        try:
            fields = obj['fields']
        except KeyError:
            self.fields.add((index, document, '_all'))
        else:
            if not fields:
                raise ElasticSearchError('No fields provided in fuzzy_like_this query "{0!r}"'.format(obj))

            self.fields.update((index, document, field) for field in fields)

    def fuzzy_like_this_field_query(self, obj, index=None, document=None):
        """Parse the given fuzzy_like_this_field query. Raises ElasticSearchError in case the query is malformed."""
        field_name = self._read_field(obj)
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in fuzzy_like_this_field query "{0!r}"'.format(obj))

    def _parse_score_function(self, obj, index, document):
        """Parse the given score function and return whether it was a success."""
        if 'script_score' in obj:
            self.permissions.add('api/feature/script')
        elif 'field_value_factor' in obj:
            try:
                self.fields.add((index, document, obj['field_value_factor']['field']))
            except (TypeError, KeyError):
                return False

        elif 'linear' in obj or 'exp' in obj or 'gauss' in obj:
            try:
                field_name = self._read_field(
                    obj.get('linear', obj.get('exp', obj.get('gauss', {}))), ['multi_value_mode'])
            except AttributeError:
                field_name = None

            if not field_name:
                return False

            self.fields.add((index, document, field_name))
        elif 'weight' in obj or 'random_score' in obj:
            pass  # These are not security relevant as of Elasticsearch v1.7
        else:
            return False

        if 'filter' in obj:
            self.filter(obj['filter'], index, document)

        return True

    def function_score_query(self, obj, index=None, document=None):
        """Parse the given function_score query. Raises ElasticSearchError in case the query is malformed."""
        if 'query' not in obj and 'filter' not in obj:
            raise ElasticSearchError('No query and filter given in function_score query "{0!r}"'.format(obj))

        try:
            functions = obj['functions']
        except KeyError:
            if not self._parse_score_function(obj, index, document):
                raise ElasticSearchError('No valid function given in function_score query "{0!r}"'.format(obj))
        else:
            if not functions:
                raise ElasticSearchError('Not any score functions given in function_score query "{0!r}"'.format(obj))

            for function_obj in functions:
                if not self._parse_score_function(function_obj, index, document):
                    raise ElasticSearchError(
                        'Invalid function "{0!r}" given in function_score query "{1!r}"'.format(function_obj, obj))

        if 'query' in obj:
            self.query(obj['query'], index, document)
        if 'filter' in obj:
            self.filter(obj['filter'], index, document)

    def fuzzy_query(self, obj, index=None, document=None):
        """Parse the given fuzzy query. Raises ElasticSearchError in case the query is malformed."""
        field_name = self._read_field(obj)
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in fuzzy query "{0!r}"'.format(obj))

    def geo_shape_query(self, obj, index=None, document=None):
        """Parse the given geo_shape query. Raises ElasticSearchError in case the query is malformed."""
        field_name = self._read_field(obj)
        if not field_name:
            raise ElasticSearchError('Missing field name in geo_shape query "{0!r}"'.format(obj))

        self.fields.add((index, document, field_name))

        try:
            shape = obj[field_name]['indexed_shape']
        except TypeError:
            raise ElasticSearchError('Invalid JSON object in geo_shape query "{0!r}"'.format(obj))
        except KeyError:
            pass
        else:
            try:
                index, document, field = shape['index'], shape['type'], shape['path']
            except KeyError:
                raise ElasticSearchError('Invalid "indexed_shape" definition in geo_shape query "{0!r}"'.format(obj))

            self.fields.add((index, document, field))

    def has_child_query(self, obj, index=None, document=None):
        """Parse the given has_child query. Raises ElasticSearchError in case the query is malformed."""
        if 'query' not in obj and 'filter' not in obj:
            raise ElasticSearchError('No query and filter given in has_child query "{0!r}"'.format(obj))

        try:
            self.documents.add((index, obj['type']))
        except KeyError:
            raise ElasticSearchError('Missing document type in has_child query "{0!r}"'.format(obj))

        if 'query' in obj:
            self.query(obj['query'], index, document)
        if 'filter' in obj:
            self.filter(obj['filter'], index, document)

    def has_parent_query(self, obj, index=None, document=None):
        """Parse the given has_parent query. Raises ElasticSearchError in case the query is malformed."""
        if 'query' not in obj and 'filter' not in obj:
            raise ElasticSearchError('No query and filter given in has_parent query "{0!r}"'.format(obj))

        try:
            self.documents.add((index, obj['parent_type']))
        except KeyError:
            raise ElasticSearchError('Missing document type in has_parent query "{0!r}"'.format(obj))

        if 'query' in obj:
            self.query(obj['query'], index, document)
        if 'filter' in obj:
            self.filter(obj['filter'], index, document)

    def ids_query(self, obj, index=None, document=None):
        """Parse the given ids query. Raises ElasticSearchError in case the query is malformed."""
        try:
            # The documentation of Elasticsearch v1.7 states that this field is optional..
            documents = obj['type']
        except KeyError:
            # ..but since it may be embedded in a indices query/filter we
            # need to register the current context if none is provided
            if index:
                self.documents.add((index, document))
        else:
            if not documents:
                raise ElasticSearchError('Not any document types given in ids query "{0!r}"'.format(obj))
            elif isinstance(documents, basestring):
                documents = [documents]

            self.documents.update((index, document) for document in documents)

    def indices_query(self, obj, index=None, document=None):
        """Parse the given indices query. Raises ElasticSearchError in case the query is malformed."""
        if 'index' not in obj and 'indices' not in obj:
            raise ElasticSearchError('Keywords "index" and "indices" missing in indices query "{0!r}"'.format(obj))
        elif 'query' not in obj:
            raise ElasticSearchError('No query given in indices query "{0!r}"'.format(obj))

        try:
            indices = obj['indices']
        except KeyError:
            indices = [obj['index']]
        else:
            if not indices:
                raise ElasticSearchError('No indices given in indices query "{0!r}"'.format(obj))

        try:
            no_match_query = obj['no_match_query']
        except KeyError:
            no_match_query = 'all'

        if isinstance(no_match_query, dict):
            self.query(no_match_query, '-' + ',-'.join(indices))
        elif no_match_query not in ['all', 'none']:
            raise ElasticSearchError('Invalid value for keyword "no_match_query" in indices query "{0!r}"'.format(obj))

        self.query(obj['query'], ','.join(indices))

    def match_all_query(self, obj, index=None, document=None):
        """Parse the given match_all query."""
        pass  # Not security relevant as of Elasticsearch v1.7

    def more_like_this_query(self, obj, index=None, document=None):
        """Parse the given more_like_this query. Raises ElasticSearchError in case the query is malformed."""
        if 'docs' not in obj and 'ids' not in obj and 'like_text' not in obj:
            raise ElasticSearchError('No valid keyword given in more_like_this query "{0!r}"'.format(obj))

        try:
            fields = obj['fields']
        except KeyError:
            fields = ['_all']
        else:
            if not fields:
                raise ElasticSearchError('No fields given in more_like_this query "{0!r}"'.format(obj))

        try:
            documents = obj['docs']
        except KeyError:
            self.fields.update((index, document, field) for field in fields)
        else:
            if not documents:
                raise ElasticSearchError('No documents given in more_like_this query "{0!r}"'.format(obj))

            for document in documents:
                try:
                    index, document = document['_index'], document['_type']
                except KeyError:
                    raise ElasticSearchError('Invalid document definition in more_like_this query "{0!r}"'.format(obj))

                # Artificial documents are intentionally ignored here because as with real documents we have
                # no knowledge about a document's fields unless specifically mentioned by a restriction
                self.fields.update((index, document, field) for field in fields)

    def nested_query(self, obj, index=None, document=None):
        """Parse the given nested query. Raises ElasticSearchError in case the query is malformed."""
        if 'path' not in obj:
            raise ElasticSearchError('Missing keyword "path" in nested query "{0!r}"'.format(obj))
        elif 'query' not in obj:
            raise ElasticSearchError('No query given in nested query "{0!r}"'.format(obj))

        self.query(obj['query'], index, document)
        self.fields.add((index, document, obj['path']))

    def prefix_query(self, obj, index=None, document=None):
        """Parse the given prefix query. Raises ElasticSearchError in case the query is malformed."""
        field_name = self._read_field(obj, ['rewrite'])
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in prefix query "{0!r}"'.format(obj))

    def query_string_query(self, obj, index=None, document=None):
        """Parse the given query_string query."""
        self.permissions.add('api/feature/queryString')

    def simple_query_string_query(self, obj, index=None, document=None):
        """Parse the given simple_query_string query."""
        self.permissions.add('api/feature/queryString')

    def range_query(self, obj, index=None, document=None):
        """Parse the given range query. Raises ElasticSearchError in case the query is malformed."""
        field_name = self._read_field(obj)
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in range query "{0!r}"'.format(obj))

    def regexp_query(self, obj, index=None, document=None):
        """Parse the given regexp query. Raises ElasticSearchError in case the query is malformed."""
        field_name = self._read_field(obj)
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in regexp query "{0!r}"'.format(obj))

    def span_first_query(self, obj, index=None, document=None):
        """Parse the given span_first query. Raises ElasticSearchError in case the query is malformed."""
        try:
            self.query(obj['match'], index, document)
        except KeyError:
            raise ElasticSearchError('Missing keyword "match" in span_first query "{0!r}"'.format(obj))

    def span_multi_query(self, obj, index=None, document=None):
        """Parse the given span_mult query. Raises ElasticSearchError in case the query is malformed."""
        try:
            self.query(obj['match'], index, document)
        except KeyError:
            raise ElasticSearchError('Missing keyword "match" in span_multi query "{0!r}"'.format(obj))

    def span_near_query(self, obj, index=None, document=None):
        """Parse the given span_near query. Raises ElasticSearchError in case the query is malformed."""
        try:
            clauses = obj['clauses']
        except KeyError:
            raise ElasticSearchError('Missing keyword "clauses" in span_near query "{0!r}"'.format(obj))

        if not clauses:
            raise ElasticSearchError('No queries given in span_near query "{0!r}"'.format(obj))

        for query in clauses:
            self.query(query, index, document)

    def span_not_query(self, obj, index=None, document=None):
        """Parse the given span_not query. Raises ElasticSearchError in case the query is malformed."""
        try:
            self.query(obj['include'], index, document)
            self.query(obj['exclude'], index, document)
        except KeyError:
            raise ElasticSearchError(
                'Mandatory keyword "include" or "exclude" missing in span_not query "{0!r}"'.format(obj))

    def span_or_query(self, obj, index=None, document=None):
        """Parse the given span_or query. Raises ElasticSearchError in case the query is malformed."""
        try:
            clauses = obj['clauses']
        except KeyError:
            raise ElasticSearchError('Missing keyword "clauses" in span_or query "{0!r}"'.format(obj))

        if not clauses:
            raise ElasticSearchError('No queries given in span_or query "{0!r}"'.format(obj))

        for query in clauses:
            self.query(query, index, document)

    def span_term_query(self, obj, index=None, document=None):
        """Parse the given span_term query. Raises ElasticSearchError in case the query is malformed."""
        field_name = self._read_field(obj)
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in span_term query "{0!r}"'.format(obj))

    def term_query(self, obj, index=None, document=None):
        """Parse the given term query. Raises ElasticSearchError in case the query is malformed."""
        field_name = self._read_field(obj)
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in term query "{0!r}"'.format(obj))

    def terms_query(self, obj, index=None, document=None):
        """Parse the given terms query. Raises ElasticSearchError in case the query is malformed."""
        field_name = self._read_field(obj, ['minimum_should_match'])
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in terms query "{0!r}"'.format(obj))

    def top_children_query(self, obj, index=None, document=None):
        """Parse the given top_children query. Simply raises ElasticSearchError because it is deprecated."""
        raise ElasticSearchError('The top_children has been obsoleted by the has_child query')

    def wildcard_query(self, obj, index=None, document=None):
        """Parse the given wildcard query. Raises ElasticSearchError in case the query is malformed."""
        field_name = self._read_field(obj, ['rewrite'])
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in wildcard query "{0!r}"'.format(obj))

    def template_query(self, obj, index=None, document=None):
        """Parse the given template query."""
        self.permissions.add('api/search/template')

    def filter(self, obj, index=None, document=None):
        """Recurse into the given filter and parse its contents."""
        self._parse_filter(*self._read_object(obj), index=index, document=document)

    def and_filter(self, obj, index=None, document=None):
        """Parse the given and filter. Raises ElasticSearchError in case the filter is malformed."""
        try:
            filters = obj['filters']
        except KeyError:
            raise ElasticSearchError('Missing keyword "filters" in and filter "{0!r}"'.format(obj))

        if not filters:
            raise ElasticSearchError('No filters given in and filter "{0!r}"'.format(obj))

        for filter in filters:
            self.filter(filter, index, document)

    def bool_filter(self, obj, index=None, document=None):
        """Parse the given bool filter. Raises ElasticSearchError in case the filter is malformed."""
        if 'must' not in obj and 'must_not' not in obj and 'should' not in obj:
            raise ElasticSearchError('No valid keyword given in bool filter "{0!r}"'.format(obj))

        for keyword in (kw for kw in ['must', 'must_not', 'should'] if kw in obj):
            if isinstance(obj[keyword], list):
                for filter in obj[keyword]:
                    self.filter(filter, index, document)
            else:
                self.filter(obj[keyword], index, document)

    def exists_filter(self, obj, index=None, document=None):
        """Parse the given exists filter. Raises ElasticSearchError in case the filter is malformed."""
        try:
            self.fields.add((index, document, obj['field']))
        except KeyError:
            raise ElasticSearchError('Missing field name in exists filter "{0!r}"'.format(obj))

    def geo_bounding_box_filter(self, obj, index=None, document=None):
        """Parse the given geo_bounding_box filter. Raises ElasticSearchError in case the filter is malformed."""
        field_name = self._read_field(obj, ['type'])
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in geo_bounding_box filter "{0!r}"'.format(obj))

    def geo_distance_filter(self, obj, index=None, document=None):
        """Parse the given geo_distance filter. Raises ElasticSearchError in case the filter is malformed."""
        field_name = self._read_field(obj, ['distance', 'distance_type', 'optimize_bbox'])
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in geo_distance_range filter "{0!r}"'.format(obj))

    def geo_distance_range_filter(self, obj, index=None, document=None):
        """Parse the given geo_distance_range filter. Raises ElasticSearchError in case the filter is malformed."""
        field_name = self._read_field(obj, ['from', 'to'])
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in geo_distance_range filter "{0!r}"'.format(obj))

    def geo_polygon_filter(self, obj, index=None, document=None):
        """Parse the given geo_polygon filter. Raises ElasticSearchError in case the filter is malformed."""
        field_name = self._read_field(obj)
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in geo_polygon filter "{0!r}"'.format(obj))

    def geo_shape_filter(self, obj, index=None, document=None):
        """Parse the given geo_shape filter. Raises ElasticSearchError in case the filter is malformed."""
        field_name = self._read_field(obj)
        if not field_name:
            raise ElasticSearchError('Missing field name in geo_shape filter "{0!r}"'.format(obj))

        self.fields.add((index, document, field_name))

        try:
            shape = obj[field_name]['indexed_shape']
        except TypeError:
            raise ElasticSearchError('Invalid JSON object in geo_shape filter "{0!r}"'.format(obj))
        except KeyError:
            pass
        else:
            try:
                index, document, field = shape['index'], shape['type'], shape['path']
            except KeyError:
                raise ElasticSearchError('Invalid "indexed_shape" definition in geo_shape filter "{0!r}"'.format(obj))

            self.fields.add((index, document, field))

    def geohash_cell_filter(self, obj, index=None, document=None):
        """Parse the given geohash_cell filter. Raises ElasticSearchError in case the filter is malformed."""
        field_name = self._read_field(obj, ['precision', 'neighbors'])
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in geohash_cell filter "{0!r}"'.format(obj))

    def has_child_filter(self, obj, index=None, document=None):
        """Parse the given has_child filter. Raises ElasticSearchError in case the filter is malformed."""
        if 'query' not in obj and 'filter' not in obj:
            raise ElasticSearchError('No query and filter given in has_child filter "{0!r}"'.format(obj))

        try:
            self.documents.add((index, obj['type']))
        except KeyError:
            raise ElasticSearchError('Missing document type in has_child filter "{0!r}"'.format(obj))

        if 'query' in obj:
            self.query(obj['query'], index, document)
        if 'filter' in obj:
            self.filter(obj['filter'], index, document)

    def has_parent_filter(self, obj, index=None, document=None):
        """Parse the given has_parent filter. Raises ElasticSearchError in case the filter is malformed."""
        if 'query' not in obj and 'filter' not in obj:
            raise ElasticSearchError('No query and filter given in has_parent filter "{0!r}"'.format(obj))

        try:
            self.documents.add((index, obj['parent_type']))
        except KeyError:
            raise ElasticSearchError('Missing document type in has_parent filter "{0!r}"'.format(obj))

        if 'query' in obj:
            self.query(obj['query'], index, document)
        if 'filter' in obj:
            self.filter(obj['filter'], index, document)

    def ids_filter(self, obj, index=None, document=None):
        """Parse the given ids filter. Raises ElasticSearchError in case the filter is malformed."""
        try:
            # The documentation of Elasticsearch v1.7 states that this field is optional..
            documents = obj['type']
        except KeyError:
            # ..but since it may be embedded in a indices query/filter we
            # need to register the current context if none is provided
            if index:
                self.documents.add((index, document))
        else:
            if not documents:
                raise ElasticSearchError('Not any document types given in ids query "{0!r}"'.format(obj))
            elif isinstance(documents, basestring):
                documents = [documents]

            self.documents.update((index, document) for document in documents)

    def indices_filter(self, obj, index=None, document=None):
        """Parse the given indices filter. Raises ElasticSearchError in case the filter is malformed."""
        if 'index' not in obj and 'indices' not in obj:
            raise ElasticSearchError('Keywords "index" and "indices" missing in indices filter "{0!r}"'.format(obj))
        elif 'filter' not in obj:
            raise ElasticSearchError('No filter given in indices filter "{0!r}"'.format(obj))

        try:
            indices = obj['indices']
        except KeyError:
            indices = [obj['index']]
        else:
            if not indices:
                raise ElasticSearchError('No indices given in indices filter "{0!r}"'.format(obj))

        try:
            no_match_filter = obj['no_match_filter']
        except KeyError:
            no_match_filter = 'all'

        if isinstance(no_match_filter, dict):
            self.filter(no_match_filter, '-' + ',-'.join(indices))
        elif no_match_filter not in ['all', 'none']:
            raise ElasticSearchError(
                'Invalid value for keyword "no_match_filter" in indices filter "{0!r}"'.format(obj))

        self.filter(obj['filter'], ','.join(indices))

    def limit_filter(self, obj, index=None, document=None):
        """Parse the given limit filter."""
        pass  # Not security relevant as of Elasticsearch v1.7

    def match_all_filter(self, obj, index=None, document=None):
        """Parse the given match_all filter."""
        pass  # Not security relevant as of Elasticsearch v1.7

    def missing_filter(self, obj, index=None, document=None):
        """Parse the given missing filter. Raises ElasticSearchError in case the filter is malformed."""
        try:
            self.fields.add((index, document, obj['field']))
        except KeyError:
            raise ElasticSearchError('Missing field name in missing filter "{0!r}"'.format(obj))

    def nested_filter(self, obj, index=None, document=None):
        """Parse the given nested filter. Raises ElasticSearchError in case the filter is malformed."""
        if 'path' not in obj:
            raise ElasticSearchError('Missing keyword "path" in nested filter "{0!r}"'.format(obj))
        elif 'filter' not in obj:
            raise ElasticSearchError('No filter given in nested filter "{0!r}"'.format(obj))

        self.filter(obj['filter'], index, document)
        self.fields.add((index, document, obj['path']))

    def not_filter(self, obj, index=None, document=None):
        """Parse the given not filter. Raises ElasticSearchError in case the filter is malformed."""
        try:
            self.filter(obj['filter'], index, document)
        except KeyError:
            raise ElasticSearchError('No filter given in not filter "{0!r}"'.format(obj))

    def or_filter(self, obj, index=None, document=None):
        """Parse the given or filter. Raises ElasticSearchError in case the filter is malformed."""
        try:
            filters = obj['filters']
        except KeyError:
            raise ElasticSearchError('Missing keyword "filters" in or filter "{0!r}"'.format(obj))

        if not filters:
            raise ElasticSearchError('No filters given in or filter "{0!r}"'.format(obj))

        for filter in filters:
            self.filter(filter, index, document)

    def prefix_filter(self, obj, index=None, document=None):
        """Parse the given prefix filter. Raises ElasticSearchError in case the filter is malformed."""
        field_name = self._read_field(obj)
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in prefix filter "{0!r}"'.format(obj))

    def query_filter(self, obj, index=None, document=None):
        """Parse the given query filter. Raises ElasticSearchError in case the filter is malformed."""
        try:
            self.query(obj['query'], index, document)
        except KeyError:
            raise ElasticSearchError('No query given in query filter "{0!r}"'.format(obj))

    def range_filter(self, obj, index=None, document=None):
        """Parse the given range filter. Raises ElasticSearchError in case the filter is malformed."""
        field_name = self._read_field(obj, ['execution'])
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in range filter "{0!r}"'.format(obj))

    def regexp_filter(self, obj, index=None, document=None):
        """Parse the given regexp filter. Raises ElasticSearchError in case the filter is malformed."""
        field_name = self._read_field(obj)
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in regexp filter "{0!r}"'.format(obj))

    def script_filter(self, obj, index=None, document=None):
        """Parse the given script filter."""
        self.permissions.add('api/feature/script')

    def term_filter(self, obj, index=None, document=None):
        """Parse the given term filter. Raises ElasticSearchError in case the filter is malformed."""
        field_name = self._read_field(obj)
        if field_name:
            self.fields.add((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in term filter "{0!r}"'.format(obj))

    def terms_filter(self, obj, index=None, document=None):
        """Parse the given terms filter. Raises ElasticSearchError in case the filter is malformed."""
        field_name = self._read_field(obj, ['execution'])
        if not field_name:
            raise ElasticSearchError('Missing field name in terms filter "{0!r}"'.format(obj))

        self.fields.add((index, document, field_name))
        if isinstance(obj[field_name], list):
            if not obj[field_name] or not isinstance(obj[field_name][0], basestring):
                raise ElasticSearchError('Invalid field value definition in terms filter "{0!r}"'.format(obj))

            self.fields.update((index, document, field) for field in obj[field_name])
        else:
            try:
                index, document, field = obj[field_name]['index'], obj[field_name]['type'], obj[field_name]['path']
            except (TypeError, KeyError):
                raise ElasticSearchError('Invalid lookup document in terms filter "{0!r}"'.format(obj))

            self.fields.add((index, document, field))

    def type_filter(self, obj, index=None, document=None):
        """Parse the given type filter. Raises ElasticSearchError in case the filter is malformed."""
        try:
            self.documents.add((index, obj['value']))
        except KeyError:
            raise ElasticSearchError('Missing type name in type filter "{0!r}"'.format(obj))


class AggregationParser(object):
    """AggregationParser object to parse Elasticsearch aggregations.

    The most common usage is probably as follows:

        parser = AggregationParser().aggregations(json_body['aggregations'])

    But the parser is not limited to this single entry point.
    Any other public method serves this purpose just as well:

        AggregationParser().avg_agg(json_object['avg'])
        AggregationParser().histogram_agg(json_object['histogram'])

    Once the parser has finished, all collected permissions, indices, documents
    and their fields can be accessed using the respective instance attributes:

        parser.permissions -> ['<permission-name>']
        parser.indices -> ['<index-name>']
        parser.documents -> [('<index-name>' | None, '<document-name>')]
        parser.fields -> [('<index-name>' | None, '<document-name>' | None, '<field-name>')]

    Any occurrence of 'None' indicates that no particular index or document is desired instead of the default ones.

    In contrast to other parsers, this will also populate an attribute called "source_requests" which possibly
    contains aggregation objects that will cause document sources to be returned in the response:

        parser.source_requests -> [('<index-name>' | None, '<document-name>' | None, dict)]

    Occurrences of 'None' have the same meaning as previously noted.
    """

    def __init__(self):
        self.permissions = set()
        self.indices = set()
        self.documents = set()
        self.fields = set()
        self.source_requests = []

        self._parsers = {
            'aggregations': self.aggregations,
            'aggs': self.aggregations,
            'min': self.min_agg,
            'max': self.max_agg,
            'sum': self.sum_agg,
            'avg': self.avg_agg,
            'stats': self.stats_agg,
            'extended_stats': self.extended_stats_agg,
            'value_count': self.value_count_agg,
            'percentiles': self.percentiles_agg,
            'percentile_ranks': self.percentile_ranks_agg,
            'cardinality': self.cardinality_agg,
            'geo_bounds': self.geo_bounds_agg,
            'top_hits': self.top_hits_agg,
            'scripted_metric': self.scripted_metric_agg,
            'global': self.global_agg,
            'filter': self.filter_agg,
            'filters': self.filters_agg,
            'missing': self.missing_agg,
            'nested': self.nested_agg,
            'reverse_nested': self.reverse_nested_agg,
            'children': self.children_agg,
            'terms': self.terms_agg,
            'significant_terms': self.significant_terms_agg,
            'range': self.range_agg,
            'date_range': self.date_range_agg,
            'ip_range': self.ip_range_agg,
            'histogram': self.histogram_agg,
            'date_histogram': self.date_histogram_agg,
            'geo_distance': self.geo_distance_agg,
            'geohash_grid': self.geohash_grid_agg
        }

    def _parse_aggregation(self, name, obj, index=None, document=None, field=None):
        """Parse the given aggregation. Raises ElasticSearchError if it is unknown."""
        try:
            return self._parsers[name](obj, index, document, field)
        except KeyError:
            raise ElasticSearchError('Unknown aggregation "{0}"'.format(name))

    def _read_aggregation(self, obj):
        """Validate and return an aggregation from the given object.
        Raises ElasticSearchError if the validation fails.

        """
        try:
            iterator = (k for k in obj.iterkeys() if k not in ['aggs', 'aggregations'])
        except AttributeError:
            raise ElasticSearchError('Invalid JSON object "{0!r}"'.format(obj))

        agg_name = next(iterator, None)
        if not agg_name:
            raise ElasticSearchError('Missing start object in "{0!r}"'.format(obj))
        elif next(iterator, None) is not None:
            raise ElasticSearchError('Multiple aggregations in "{0!r}"'.format(obj))
        elif not isinstance(obj[agg_name], dict) and (agg_name != 'filters' or not isinstance(obj[agg_name], list)):
            raise ElasticSearchError('Invalid start object "{0!r}"'.format(obj[agg_name]))

        return agg_name, obj[agg_name]

    def _validate_keywords(self, name, obj, known_keywords):
        """Check whether the given aggregation contains any unknown keywords and raise ElasticSearchError if so."""
        unknown_keyword = next((k for k in obj.iterkeys() if k not in known_keywords), None)
        if unknown_keyword is not None:
            raise ElasticSearchError('Unknown keyword "{0}" in {1} aggregation "{2!r}"'
                                     ''.format(unknown_keyword, name, obj))

    def _default_parser(self, name, obj, index=None, document=None, field=None):
        """Parse the given aggregation in a generic manner. Raises ElasticSearchError in case it is malformed."""
        self._validate_keywords(name, obj, ['field', 'script', 'script_id', 'script_file',
                                            'lang', 'params', 'script_values_sorted'])

        try:
            field = obj['field']
        except KeyError:
            pass
        else:
            if not field:
                raise ElasticSearchError('Empty field name in {0} aggregation "{1!r}"'.format(name, obj))

            self.fields.add((index, document, field))

        if 'script' in obj or 'script_id' in obj or 'script_path' in obj:
            self.permissions.add('api/feature/script')

        return index, document, field

    def aggregations(self, obj, index=None, document=None, field=None):
        """Recurse into the given aggregations and parse their contents.
        Raises ElasticSearchError in case they are malformed.

        """
        if not isinstance(obj, dict):
            raise ElasticSearchError('Invalid JSON object "{0!r}"'.format(obj))

        current_context = (index, document, field)
        for agg_body in obj.itervalues():
            new_context = self._parse_aggregation(*self._read_aggregation(agg_body),
                                                  index=index, document=document, field=field)

            if 'aggs' in agg_body or 'aggregations' in agg_body:
                self.aggregations(agg_body.get('aggs', agg_body.get('aggregations')), *(new_context or current_context))

    def min_agg(self, obj, index=None, document=None, field=None):
        """Parse the given min aggregation. Raises ElasticSearchError in case it is malformed."""
        return self._default_parser('min', obj, index, document, field)

    def max_agg(self, obj, index=None, document=None, field=None):
        """Parse the given max aggregation. Raises ElasticSearchError in case it is malformed."""
        return self._default_parser('max', obj, index, document, field)

    def sum_agg(self, obj, index=None, document=None, field=None):
        """Parse the given sum aggregation. Raises ElasticSearchError in case it is malformed."""
        return self._default_parser('sum', obj, index, document, field)

    def avg_agg(self, obj, index=None, document=None, field=None):
        """Parse the given avg aggregation. Raises ElasticSearchError in case it is malformed."""
        return self._default_parser('avg', obj, index, document, field)

    def stats_agg(self, obj, index=None, document=None, field=None):
        """Parse the given stats aggregation. Raises ElasticSearchError in case it is malformed."""
        return self._default_parser('stats', obj, index, document, field)

    def extended_stats_agg(self, obj, index=None, document=None, field=None):
        """Parse the given extended_stats aggregation. Raises ElasticSearchError in case it is malformed."""
        return self._default_parser('extended_stats', obj, index, document, field)

    def value_count_agg(self, obj, index=None, document=None, field=None):
        """Parse the given value_count aggregation. Raises ElasticSearchError in case it is malformed."""
        return self._default_parser('value_count', obj, index, document, field)

    def percentiles_agg(self, obj, index=None, document=None, field=None):
        """Parse the given percentiles aggregation. Raises ElasticSearchError in case it is malformed."""
        return self._default_parser('percentiles', obj, index, document, field)

    def percentile_ranks_agg(self, obj, index=None, document=None, field=None):
        """Parse the given percentile_ranks aggregation. Raises ElasticSearchError in case it is malformed."""
        return self._default_parser('percentile_ranks', obj, index, document, field)

    def cardinality_agg(self, obj, index=None, document=None, field=None):
        """Parse the given cardinality aggregation. Raises ElasticSearchError in case it is malformed."""
        return self._default_parser('cardinality', obj, index, document, field)

    def geo_bounds_agg(self, obj, index=None, document=None, field=None):
        """Parse the given geo_bounds aggregation. Raises ElasticSearchError in case it is malformed."""
        return self._default_parser('geo_bounds', obj, index, document, field)

    def top_hits_agg(self, obj, index=None, document=None, field=None):
        """Parse the given top_hits aggregation. Raises ElasticSearchError in case it is malformed."""
        self._validate_keywords('top_hits', obj, ['sort', '_source', 'highlight', 'explain', 'script_fields',
                                                  'fielddata_fields', 'size', 'from'])

        self.source_requests.append((index, document, obj))
        if obj.get('_source'):
            try:
                self.fields.update((index, document, f) for f in parse_source_filter(obj['_source']))
            except ValueError as error:
                raise ElasticSearchError('Invalid source filter in top_hits aggregation "{0!r}" ({1})', obj, error)

        if 'highlight' in obj:
            parser = HighlightParser()
            parser.parse(obj['highlight'])
            self.permissions |= parser.permissions
            self.indices |= parser.indices
            self.documents |= parser.documents
            self.fields |= parser.fields

        if 'explain' in obj:
            self.permissions.add('api/search/explain')

        if 'script_fields' in obj:
            self.permissions.add('api/feature/script')

        if 'fielddata_fields' in obj:
            if isinstance(obj['fielddata_fields'], list):
                self.fields.update((index, document, f) for f in obj['fielddata_fields'])
            else:
                raise ElasticSearchError(
                    'Invalid fielddata_fields definition in top_hits aggregation "{0!r}"'.format(obj))

        if 'sort' in obj:
            try:
                for field in obj['sort'].iterkeys():
                    if field:
                        self.fields.add((index, document, field))
            except AttributeError:
                raise ElasticSearchError('Invalid JSON object "{0!r}"'.format(obj['sort']))

    def scripted_metric_agg(self, obj, index=None, document=None, field=None):
        """Parse the given scripted_metric aggregation."""
        self.permissions.add('api/feature/script')

    def global_agg(self, obj, index=None, document=None, field=None):
        """Parse the given global aggregation. Raises ElasticSearchError in case it is malformed."""
        if obj:
            raise ElasticSearchError('Aggregations of type global have usually an empty body, wouldn\'t they?')

    def filter_agg(self, obj, index=None, document=None, field=None):
        """Parse the given filter aggregation. Raises ElasticSearchError in case it is malformed."""
        parser = QueryDslParser()
        parser.filter(obj, index, document)
        self.permissions |= parser.permissions
        self.indices |= parser.indices
        self.documents |= parser.documents
        self.fields |= parser.fields

    def filters_agg(self, obj, index=None, document=None, field=None):
        """Parse the given filters aggregation. Raises ElasticSearchError in case it is malformed."""
        if isinstance(obj, list):
            iterator = obj
        else:
            try:
                iterator = obj.itervalues
            except AttributeError:
                raise ElasticSearchError('Invalid JSON object "{0!r}"'.format(obj))

        for filter in iterator:
            parser = QueryDslParser()
            parser.filter(filter, index, document)
            self.permissions |= parser.permissions
            self.indices |= parser.indices
            self.documents |= parser.documents
            self.fields |= parser.fields

    def missing_agg(self, obj, index=None, document=None, field=None):
        """Parse the given missing aggregation. Raises ElasticSearchError in case it is malformed."""
        return self._default_parser('missing', obj, index, document, field)

    def nested_agg(self, obj, index=None, document=None, field=None):
        """Parse the given nested aggregation. Raises ElasticSearchError in case it is malformed."""
        self._validate_keywords('nested', obj, ['path'])

        try:
            path = obj['path']
        except KeyError:
            raise ElasticSearchError('Missing keyword "path" in nested aggregation "{0!r}"'.format(obj))
        else:
            if not path:
                raise ElasticSearchError('Empty field path in nested aggregation "{0!r}"'.format(obj))

            self.fields.add((index, document, path))
            return index, document, path

    def reverse_nested_agg(self, obj, index=None, document=None, field=None):
        """Parse the given reverse_nested aggregation."""
        self._validate_keywords('reverse_nested', obj, ['path'])

        try:
            path = obj['path']
        except KeyError:
            if field is None:
                raise ElasticSearchError('No field path found in the parser\'s current context. Make sure that the'
                                         ' reverse_nested aggregation "{0!r}" is part of a nested aggregation!'
                                         ''.format(obj))

            path = field.split('.', 1)[0]
        else:
            if not path:
                raise ElasticSearchError('Empty field path in reverse_nested aggregation "{0!r}"'.format(obj))

        self.fields.add((index, document, path))
        return index, document, path

    def children_agg(self, obj, index=None, document=None, field=None):
        """Parse the given children aggregation. Raises ElasticSearchError in case it is malformed."""
        self._validate_keywords('children', obj, ['type'])

        try:
            document = obj['type']
        except KeyError:
            raise ElasticSearchError('Missing keyword "type" in children aggregation "{0!r}"'.format(obj))
        else:
            if not document:
                raise ElasticSearchError('Empty type name in children aggregation "{0!r}"'.format(obj))

            self.documents.add((index, document))
            return index, document, field

    def terms_agg(self, obj, index=None, document=None, field=None):
        """Parse the given terms aggregation. Raises ElasticSearchError in case it is malformed."""
        self._validate_keywords('terms', obj, ['field', 'size', 'shard_size', 'show_term_doc_count_error', 'order',
                                               'min_doc_count', 'shard_min_doc_count', 'script', 'script_id',
                                               'script_file', 'params', 'include', 'exclude', 'collect_mode',
                                               'execution_hint'])
        try:
            field = obj['field']
        except KeyError:
            pass
        else:
            if not field:
                raise ElasticSearchError('Empty field name in terms aggregation "{0!r}"'.format(obj))

            self.fields.add((index, document, field))

        if 'script' in obj or 'script_id' in obj or 'script_file' in obj:
            self.permissions.add('api/feature/script')

        return index, document, field

    def significant_terms_agg(self, obj, index=None, document=None, field=None):
        """Parse the given significant_terms aggregation."""
        self.permissions.add('api/feature/experimental')

    def range_agg(self, obj, index=None, document=None, field=None):
        """Parse the given range aggregation. Raises ElasticSearchError in case it is malformed."""
        self._validate_keywords(
            'range', obj, ['field', 'ranges', 'keyed', 'script', 'script_id', 'script_file', 'params'])

        try:
            field = obj['field']
        except KeyError:
            raise ElasticSearchError('Missing keyword "field" in range aggregation "{0!r}"'.format(obj))
        else:
            if not field:
                raise ElasticSearchError('Empty field name in range aggregation "{0!r}"'.format(obj))

            self.fields.add((index, document, field))

        if 'script' in obj or 'script_id' in obj or 'script_file' in obj:
            self.permissions.add('api/feature/script')

        return index, document, field

    def date_range_agg(self, obj, index=None, document=None, field=None):
        """Parse the given date_range aggregation. Raises ElasticSearchError in case it is malformed."""
        self._validate_keywords(
            'date_range', obj, ['field', 'format', 'ranges', 'script', 'script_id', 'script_file', 'params'])

        try:
            field = obj['field']
        except KeyError:
            raise ElasticSearchError('Missing keyword "field" in date_range aggregation "{0!r}"'.format(obj))
        else:
            if not field:
                raise ElasticSearchError('Empty field name in date_range aggregation "{0!r}"'.format(obj))

            self.fields.add((index, document, field))

        if 'script' in obj or 'script_id' in obj or 'script_file' in obj:
            self.permissions.add('api/feature/script')

        return index, document, field

    def ip_range_agg(self, obj, index=None, document=None, field=None):
        """Parse the given ip_range aggregation. Raises ElasticSearchError in case it is malformed."""
        self._validate_keywords('ip_range', obj, ['field', 'ranges', 'script', 'script_id', 'script_file', 'params'])

        try:
            field = obj['field']
        except KeyError:
            raise ElasticSearchError('Missing keyword "field" in ip_range aggregation "{0!r}"'.format(obj))
        else:
            if not field:
                raise ElasticSearchError('Empty field name in ip_range aggregation "{0!r}"'.format(obj))

            self.fields.add((index, document, field))

        if 'script' in obj or 'script_id' in obj or 'script_file' in obj:
            self.permissions.add('api/feature/script')

        return index, document, field

    def histogram_agg(self, obj, index=None, document=None, field=None):
        """Parse the given histogram aggregation. Raises ElasticSearchError in case it is malformed."""
        self._validate_keywords('histogram', obj, ['field', 'interval', 'min_doc_count', 'extended_bounds',
                                                   'order', 'script', 'script_id', 'script_file', 'params'])

        try:
            field = obj['field']
        except KeyError:
            raise ElasticSearchError('Missing keyword "field" in histogram aggregation "{0!r}"'.format(obj))
        else:
            if not field:
                raise ElasticSearchError('Empty field name in histogram aggregation "{0!r}"'.format(obj))

            self.fields.add((index, document, field))

        if 'script' in obj or 'script_id' in obj or 'script_file' in obj:
            self.permissions.add('api/feature/script')

        return index, document, field

    def date_histogram_agg(self, obj, index=None, document=None, field=None):
        """Parse the given date_histogram aggregation. Raises ElasticSearchError in case it is malformed."""
        self._validate_keywords('date_histogram', obj, ['field', 'interval', 'pre_zone', 'post_zone', 'time_zone',
                                                        'pre_zone_adjust_large_interval', 'pre_offset', 'post_offset',
                                                        'offset', 'format', 'min_doc_count', 'extended_bounds',
                                                        'order', 'script', 'script_id', 'script_file', 'params'])
        try:
            field = obj['field']
        except KeyError:
            raise ElasticSearchError('Missing keyword "field" in date_histogram aggregation "{0!r}"'.format(obj))
        else:
            if not field:
                raise ElasticSearchError('Empty field name in date_histogram aggregation "{0!r}"'.format(obj))

            self.fields.add((index, document, field))

        if 'script' in obj or 'script_id' in obj or 'script_file' in obj:
            self.permissions.add('api/feature/script')

        return index, document, field

    def geo_distance_agg(self, obj, index=None, document=None, field=None):
        """Parse the given geo_distance aggregation. Raises ElasticSearchError in case it is malformed."""
        self._validate_keywords('geo_distance', obj, ['field', 'origin', 'ranges', 'unit', 'distance_type'])

        try:
            field = obj['field']
        except KeyError:
            raise ElasticSearchError('Missing keyword "field" in geo_distance aggregation "{0!r}"'.format(obj))
        else:
            if not field:
                raise ElasticSearchError('Empty field name in geo_distance aggregation "{0!r}"'.format(obj))

            self.fields.add((index, document, field))
            return index, document, field

    def geohash_grid_agg(self, obj, index=None, document=None, field=None):
        """Parse the given geohash_grid aggregation. Raises ElasticSearchError in case it is malformed."""
        self._validate_keywords('geohash_grid', obj, ['field', 'precision', 'size', 'shard_size'])

        try:
            field = obj['field']
        except KeyError:
            raise ElasticSearchError('Missing keyword "field" in geohash_grid aggregation "{0!r}"'.format(obj))
        else:
            if not field:
                raise ElasticSearchError('Empty field name in geohash_grid aggregation "{0!r}"'.format(obj))

            self.fields.add((index, document, field))
            return index, document, field


def parse_source_filter(data):
    """Parse the given source filter and return all requested field names, if any.
    Raises ValueError in case the filter is malformed.

    """
    assert data, 'Empty source filter given'

    seq = []
    if isinstance(data, basestring):
        seq = [data]
    elif isinstance(data, list):
        seq = data
    else:
        try:
            unknown = next((k for k in data.iterkeys() if k not in ['include', 'exclude']), None)
            if unknown is not None:
                raise ValueError('Unknown keyword "{0}"'.format(unknown))

            seq = data.get('include', [])
        except AttributeError:
            raise ValueError('Invalid JSON object "{0!r}"'.format(data))

    return seq


class HighlightParser(object):
    """HighlightParser object to parse Elasticsearch highlight definitions.

    The usage is as follows:

        parser = HighlightParser().parse(json_body['highlight'])

    Once the parser has finished, all collected permissions, indices, documents
    and their fields can be accessed using the respective instance attributes:

        parser.permissions -> ['<permission-name>']
        parser.indices -> ['<index-name>']
        parser.documents -> [('<index-name>' | None, '<document-name>')]
        parser.fields -> [('<index-name>' | None, '<document-name>' | None, '<field-name>')]

    Any occurrence of 'None' indicates that no particular index or document is desired instead of the default ones.
    """

    _global_settings = [
        'pre_tags',
        'post_tags',
        'tags_schema',
        'fragment_size',
        'number_of_fragments',
        'no_match_size',
        'encoder',
        'order',
        'require_field_match',
        'boundary_chars',
        'boundary_max_scan',
        'matched_fields'
    ]

    def __init__(self):
        self.permissions = set()
        self.indices = set()
        self.documents = set()
        self.fields = set()

    def _validate_keywords(self, obj, known_keywords):
        """Check whether the given object contains any unknown keywords and raise ElasticSearchError if so."""
        unknown_keyword = next((k for k in obj.iterkeys() if k not in known_keywords), None)
        if unknown_keyword is not None:
            raise ElasticSearchError('Unknown keyword "{0}" in highlight object "{1!r}"'.format(unknown_keyword, obj))

    def parse(self, highlight, index=None, document=None):
        """Parse the given highlight object. Raises ElasticSearchError in case it is malformed."""
        if not isinstance(highlight, dict):
            raise ElasticSearchError('Invalid highlight object "{0!r}"'.format(highlight))

        self._validate_keywords(highlight, ['fields'] + self._global_settings)

        try:
            if isinstance(highlight['fields'], list):
                fields = [t for d in highlight['fields'] for t in d.iteritems()]
            else:
                fields = highlight['fields'].iteritems()
        except AttributeError:
            raise ElasticSearchError('Invalid fields definition in highlight object "{0!r}"'.format(highlight))

        field_settings = ['type', 'force_source', 'highlight_query'] + self._global_settings
        for field, field_obj in fields:
            self._validate_keywords(field_obj, field_settings)
            if 'highlight_query' in field_obj:
                parser = QueryDslParser()
                parser.query(field_obj['highlight_query'], index, document)
                self.permissions |= parser.permissions
                self.indices |= parser.indices
                self.documents |= parser.documents
                self.fields |= parser.fields

            if 'matched_fields' in field_obj:
                self.fields.update((index, document, f) for f in field_obj['matched_fields'])

            self.fields.add((index, document, field))
