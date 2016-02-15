# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import time
import urllib
import threading

import requests

from elasticarmor.util.rwlock import ReadWriteLock
from elasticarmor.util.mixins import LoggingAware

__all__ = ['ElasticConnection']

DEFAULT_TIMEOUT = 5  # Seconds
CHECK_REACHABILITY_INTERVAL = 900  # Seconds


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
                    self.log.debug('Node "%s" is still unreachable. Error: %s', node, error)

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
        """Forward the given request to Elasticsearch and return its response.
        Returns None if it was not possible to receive a response."""
        prepared_request = requests.PreparedRequest()
        prepared_request.prepare_method(request.command)
        prepared_request.prepare_headers(request.headers)
        prepared_request.prepare_body(request.body, None)
        encoded_query = urllib.urlencode(request.query, True)
        self.log.debug('Forwarding request "%s %s?%s" to Elasticsearch...',
                       request.command, request.path, encoded_query)

        first_error = None
        with requests.Session() as session:
            for node in self._reachable_nodes:
                prepared_request.prepare_url(node + request.path, encoded_query)

                try:
                    # TODO: Interpret the timeout= query parameter for Elasticsearch
                    response = session.send(prepared_request, stream=True, timeout=DEFAULT_TIMEOUT)
                except requests.Timeout:
                    self.log.warning('Node "%s" timed out.', node)
                    self._mark_as_unreachable(node)
                except requests.RequestException as error:
                    self.log.warning('Failed to connect to node "%s". An error occurred: %s', node, error)
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
        else:
            self.log.debug('No response received from any of the configured Elasticsearch nodes.')
