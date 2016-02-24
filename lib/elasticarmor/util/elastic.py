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
