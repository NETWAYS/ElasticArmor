# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import cStringIO
import os
import json

from elasticarmor.util.http import HttpHeaders
from elasticarmor.util.mixins import LoggingAware

__all__ = ['ElasticRequest', 'ElasticResponse', 'RequestError', 'PermissionError']


class _RequestRegistry(type):
    """
    A metaclass to register every class derived from ElasticRequest.

    """
    registry = []

    def __new__(mcs, class_name, base_classes, namespace):
        class_obj = super(_RequestRegistry, mcs).__new__(mcs, class_name, base_classes, namespace)
        if class_name != 'ElasticRequest':
            mcs.registry.append(class_obj)
            mcs.registry = sorted(mcs.registry, key=lambda c: c.priority, reverse=True)

        return class_obj


class RequestError(Exception):
    """Raised by instances of ElasticRequest. This is the base
    class for all other request inspection related exceptions."""

    def __init__(self, status_code, reason):
        self.status_code = status_code
        self.reason = reason


class PermissionError(RequestError):
    """Raised by instances of ElasticRequest in case of insufficient permissions to process a request."""
    status_code = 403

    def __init__(self, reason):
        self.reason = reason


class ElasticResponse(object):
    """Response object which may be provided by instances of ElasticRequest.

    Any instance of ElasticRequest might return this to indicate that
    Elasticsearch does not need to be contacted to provide a response
    to the client.
    """

    def __init__(self):
        self.reason = None
        self.options = None
        self.content = None
        self.status_code = None
        self.headers = HttpHeaders()

    @property
    def raw(self):
        # Helper required to make sure this is compatible to
        # how requests.Response allows to stream its payload
        return self

    def _stream_string(self, chunk_size):
        file_like = cStringIO.StringIO(self.content)
        while True:
            chunk = file_like.read(chunk_size)
            if chunk:
                yield chunk
            else:
                raise StopIteration()

    def _stream_iterable(self, chunk_size):
        rest = ''
        for line in self.content:
            rest += line
            if len(rest) >= chunk_size:
                yield rest[:chunk_size]
                rest = rest[chunk_size:]

        if rest:
            yield rest

        raise StopIteration()

    def stream(self, chunk_size, decode_content):
        """Return the payload as chunks of the given max-size."""
        if callable(self.content):
            return self.content(chunk_size)
        elif isinstance(self.content, basestring):
            return self._stream_string(chunk_size)
        else:
            return self._stream_iterable(chunk_size)


class ElasticRequest(LoggingAware, object):
    """Base class for all Elasticsearch request handlers.

    Every derived class placed in this sub-module is automatically being imported and used.
    """
    __metaclass__ = _RequestRegistry

    # The priority of a request handler. The higher the value, the earlier a request handler is
    # asked to process a request. If you're not competing with other handlers, leave the default
    priority = 0

    def __init__(self, context, **kwargs):
        super(ElasticRequest, self).__init__()
        self._json = None

        self.context = context
        for name, value in kwargs.iteritems():
            setattr(self, name, value)

    def __getattr__(self, name):
        """Access the given attribute on the context's request and return its value.
        Raises AttributeError if the attribute is not found.

        """
        value = getattr(self.context.request, name)
        setattr(self, name, value)
        return value

    @staticmethod
    def create_request(context, **kwargs):
        """Return a instance of the first matching request handler
        for the given request. Returns None if no handler matches.

        """
        for class_obj in _RequestRegistry.registry:
            handler = class_obj(context, **kwargs)
            if handler.is_valid():
                return handler

    @classmethod
    def clear_caches(cls):
        """Clear the cache of all registered request handlers."""
        for class_obj in _RequestRegistry.registry:
            cls.log.debug('Clearing cache of request handler "%s"...', class_obj.__name__)
            class_obj.clear_cache()

    @classmethod
    def clear_cache(cls):
        """Clear any caches. Gets called once the user reloads the application."""
        pass

    @property
    def json(self):
        if self._json is None:
            self._json = json.loads(self.body)

        return self._json

    def is_valid(self):
        """Take a quick look at the request and return whether it can be handled or not."""
        raise NotImplementedError()

    def inspect(self, client):
        """Take a deeper look at the request and check if the given client may do
        what is requested. Raising a instance of RequestError here immediately
        causes an error response being sent to the client.

        Return a instance of ElasticResponse to directly provide a response to the
        client without contacting Elasticsearch.

        """
        raise NotImplementedError()

    def prepare_transformation(self, response):
        """Prepare any required transformations for the given response and
        return a reason if a transformation is about to be applied on it.

        """
        pass

    def transform(self, stream):
        """Apply required transformations on the given response-body stream and return a new iterable."""
        return stream


# Dynamically import all sub-modules to avoid manually adjusting
# this file every time we'll support an additional request
for module in os.listdir(os.path.dirname(__file__)):
    if module != '__init__.py' and module.endswith('.py'):
        __import__('elasticarmor.request.' + module[:-3])
