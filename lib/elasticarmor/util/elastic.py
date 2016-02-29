# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import time
import urllib
import threading

import requests

from elasticarmor.util import format_elasticsearch_error
from elasticarmor.util.rwlock import ReadWriteLock
from elasticarmor.util.mixins import LoggingAware

__all__ = ['ElasticSearchError', 'ElasticConnection', 'ElasticObject', 'ElasticRole']

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


class QueryDslParser(object):
    def __init__(self):
        self.permissions = []
        self.indices = []
        self.documents = []
        self.fields = []

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
            object_name = next(data.iterkeys())
        except AttributeError:
            raise ElasticSearchError('Invalid JSON object "{0!r}"'.format(data))

        if not object_name:
            raise ElasticSearchError('Missing start object')
        elif not isinstance(data[object_name], dict):
            raise ElasticSearchError('Invalid start object "{0!r}"'.format(data[object_name]))

        return object_name, data[object_name]

    def _read_field(self, obj, blacklist=None):
        """Identify and return the field name in the given object."""
        return next(k for k in obj.iterkeys() if k[0] != '_' and (not blacklist or k not in blacklist))

    def query(self, obj, index=None, document=None):
        """Recurse into the given query and parse its contents."""
        self._parse_query(*self._read_object(obj), index=index, document=document)

    def match_query(self, obj, index=None, document=None):
        """Parse the given match query. Raises ElasticSearchError in case the query is malformed."""
        field_name = self._read_field(obj)
        if field_name:
            self.fields.append((index, document, field_name))
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

        self.fields.extend((index, document, field) for field in fields)

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
            self.fields.append((index, document, field_name))
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
            self.fields.append((index, document, '_all'))
        else:
            if not fields:
                raise ElasticSearchError('No fields provided in fuzzy_like_this query "{0!r}"'.format(obj))

            self.fields.extend((index, document, field) for field in fields)

    def fuzzy_like_this_field_query(self, obj, index=None, document=None):
        """Parse the given fuzzy_like_this_field query. Raises ElasticSearchError in case the query is malformed."""
        field_name = self._read_field(obj)
        if field_name:
            self.fields.append((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in fuzzy_like_this_field query "{0!r}"'.format(obj))

    def _parse_score_function(self, obj, index, document):
        """Parse the given score function and return whether it was a success."""
        if 'script_score' in obj:
            self.permissions.append('<scripted_query_dsl>')  # TODO: Use a proper permission name
        elif 'field_value_factor' in obj:
            try:
                self.fields.append((index, document, obj['field_value_factor']['field']))
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

            self.fields.append((index, document, field_name))
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
            self.fields.append((index, document, field_name))
        else:
            raise ElasticSearchError('Missing field name in fuzzy query "{0!r}"'.format(obj))

    def geo_shape_query(self, obj, index=None, document=None):
        """Parse the given geo_shape query. Raises ElasticSearchError in case the query is malformed."""
        field_name = next(obj.iterkeys())
        if not field_name:
            raise ElasticSearchError('Missing field name in geo_shape query "{0!r}"'.format(obj))

        self.fields.append((index, document, field_name))

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

            self.fields.append((index, document, field))

    def has_child_query(self, obj, index=None, document=None):
        """Parse the given has_child query. Raises ElasticSearchError in case the query is malformed."""
        if 'query' not in obj and 'filter' not in obj:
            raise ElasticSearchError('No query and filter given in has_child query "{0!r}"'.format(obj))

        try:
            self.documents.append((index, obj['type']))
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
            self.documents.append((index, obj['parent_type']))
        except KeyError:
            raise ElasticSearchError('Missing document type in has_parent query "{0!r}"'.format(obj))

        if 'query' in obj:
            self.query(obj['query'], index, document)
        if 'filter' in obj:
            self.filter(obj['filter'], index, document)

    def ids_query(self, obj, index=None, document=None):
        """Parse the given ids query. Raises ElasticSearchError in case the query is malformed."""
        try:
            documents = obj['type']
        except KeyError:
            documents = [document or '_all']
        else:
            if not documents:
                raise ElasticSearchError('Not any document types given in ids query "{0!r}"'.format(obj))
            elif isinstance(documents, basestring):
                documents = [documents]

        self.documents.extend((index, document) for document in documents)

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
        pass

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
            self.fields.extend((index, document, field) for field in fields)
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
                self.fields.extend((index, document, field) for field in fields)

    def nested_query(self, obj, index=None, document=None):
        """Parse the given nested query. Raises ElasticSearchError in case the query is malformed."""
        if 'path' not in obj:
            raise ElasticSearchError('Missing keyword "path" in nested query "{0!r}"'.format(obj))
        elif 'query' not in obj:
            raise ElasticSearchError('No query given in nested query "{0!r}"'.format(obj))

        self.query(obj['query'], index, document)
        self.fields.append((index, document, obj['path']))

    def prefix_query(self, obj, index=None, document=None):
        pass

    def query_string_query(self, obj, index=None, document=None):
        """Parse the given query_string query."""
        self.permissions.append('<query_string_permission>')  # TODO: Use a proper permission name

    def simple_query_string_query(self, obj, index=None, document=None):
        """Parse the given simple_query_string query."""
        self.permissions.append('<query_string_permission>')  # TODO: Use a proper permission name

    def range_query(self, obj, index=None, document=None):
        pass

    def regexp_query(self, obj, index=None, document=None):
        pass

    def span_first_query(self, obj, index=None, document=None):
        pass

    def span_multi_query(self, obj, index=None, document=None):
        pass

    def span_near_query(self, obj, index=None, document=None):
        pass

    def span_not_query(self, obj, index=None, document=None):
        pass

    def span_or_query(self, obj, index=None, document=None):
        pass

    def span_term_query(self, obj, index=None, document=None):
        pass

    def term_query(self, obj, index=None, document=None):
        pass

    def terms_query(self, obj, index=None, document=None):
        pass

    def top_children_query(self, obj, index=None, document=None):
        """Parse the given top_children query. Simply raises ElasticSearchError because it is deprecated."""
        raise ElasticSearchError('The top_children has been obsoleted by the has_child query')

    def wildcard_query(self, obj, index=None, document=None):
        pass

    def template_query(self, obj, index=None, document=None):
        """Parse the given template query."""
        self.permissions.append('<search_template_permission>')  # TODO: Use a proper permission name

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
        pass

    def geo_bounding_box_filter(self, obj, index=None, document=None):
        pass

    def geo_distance_filter(self, obj, index=None, document=None):
        pass

    def geo_distance_range_filter(self, obj, index=None, document=None):
        pass

    def geo_polygon_filter(self, obj, index=None, document=None):
        pass

    def geo_shape_filter(self, obj, index=None, document=None):
        """Parse the given geo_shape filter. Raises ElasticSearchError in case the filter is malformed."""
        field_name = next(obj.iterkeys())
        if not field_name:
            raise ElasticSearchError('Missing field name in geo_shape filter "{0!r}"'.format(obj))

        self.fields.append((index, document, field_name))

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

            self.fields.append((index, document, field))

    def geohash_cell_filter(self, obj, index=None, document=None):
        pass

    def has_child_filter(self, obj, index=None, document=None):
        """Parse the given has_child filter. Raises ElasticSearchError in case the filter is malformed."""
        if 'query' not in obj and 'filter' not in obj:
            raise ElasticSearchError('No query and filter given in has_child filter "{0!r}"'.format(obj))

        try:
            self.documents.append((index, obj['type']))
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
            self.documents.append((index, obj['parent_type']))
        except KeyError:
            raise ElasticSearchError('Missing document type in has_parent filter "{0!r}"'.format(obj))

        if 'query' in obj:
            self.query(obj['query'], index, document)
        if 'filter' in obj:
            self.filter(obj['filter'], index, document)

    def ids_filter(self, obj, index=None, document=None):
        pass

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
        pass

    def nested_filter(self, obj, index=None, document=None):
        """Parse the given nested filter. Raises ElasticSearchError in case the filter is malformed."""
        if 'path' not in obj:
            raise ElasticSearchError('Missing keyword "path" in nested filter "{0!r}"'.format(obj))
        elif 'filter' not in obj:
            raise ElasticSearchError('No filter given in nested filter "{0!r}"'.format(obj))

        self.filter(obj['filter'], index, document)
        self.fields.append((index, document, obj['path']))

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
        pass

    def query_filter(self, obj, index=None, document=None):
        """Parse the given query filter. Raises ElasticSearchError in case the filter is malformed."""
        try:
            self.query(obj['query'], index, document)
        except KeyError:
            raise ElasticSearchError('No query given in query filter "{0!r}"'.format(obj))

    def range_filter(self, obj, index=None, document=None):
        pass

    def regexp_filter(self, obj, index=None, document=None):
        pass

    def script_filter(self, obj, index=None, document=None):
        """Parse the given script filter."""
        self.permissions.append('<scripted_query_dsl>')  # TODO: Use a proper permission name

    def term_filter(self, obj, index=None, document=None):
        pass

    def terms_filter(self, obj, index=None, document=None):
        """Parse the given terms filter. Raises ElasticSearchError in case the filter is malformed."""
        field_name = next(obj.iterkeys())
        if not field_name:
            raise ElasticSearchError('Missing field name in terms filter "{0!r}"'.format(obj))

        self.fields.append((index, document, field_name))
        if isinstance(obj[field_name], list):
            if not obj[field_name] or not isinstance(obj[field_name][0], basestring):
                raise ElasticSearchError('Invalid field value definition in terms filter "{0!r}"'.format(obj))

            self.fields.extend((index, document, field) for field in obj[field_name])
        else:
            try:
                index, document, field = obj[field_name]['index'], obj[field_name]['type'], obj[field_name]['path']
            except (TypeError, KeyError):
                raise ElasticSearchError('Invalid lookup document in terms filter "{0!r}"'.format(obj))

            self.fields.append((index, document, field))

    def type_filter(self, obj, index=None, document=None):
        pass
