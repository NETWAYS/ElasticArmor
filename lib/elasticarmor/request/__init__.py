# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import os

from requests.structures import CaseInsensitiveDict

from elasticarmor.util.mixins import LoggingAware

__all__ = ['ElasticRequest', 'DummyResponse', 'ValidationError', 'RequestError', 'PermissionError']


class _RequestRegistry(type):
    """
    A metaclass to register every class derived from ElasticRequest.

    """
    registry = []

    def __new__(mcs, class_name, base_classes, namespace):
        class_obj = super(_RequestRegistry, mcs).__new__(mcs, class_name, base_classes, namespace)
        if class_name != 'ElasticRequest':
            mcs.registry.append(class_obj)

        return class_obj


class ValidationError(Exception):
    """Raised by instances of ElasticRequest in case validating a request has failed."""
    pass


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


class DummyResponse(object):
    """Response dummy to mimic the basic behaviour of requests.Response.

    Any instance of ElasticRequest might return this to indicate that
    Elasticsearch does not need to be contacted to provide a response
    to the client.
    """

    def __init__(self):
        self.reason = None
        self.content = None
        self.status_code = None
        self.headers = CaseInsensitiveDict()


class ElasticRequest(LoggingAware, object):
    """Base class for all Elasticsearch request handlers.

    Every derived class placed in this sub-module is automatically being imported and used.
    """
    __metaclass__ = _RequestRegistry

    def __init__(self, method, path, query, headers, body):
        super(ElasticRequest, self).__init__()

        self.path = path
        self.body = body
        self.query = query
        self.method = method
        self.headers = headers

        self.validate()

    @staticmethod
    def create_request(method, path, query, headers, body):
        """Return a instance of the first matching request handler
        for the given request. Returns None if no handler matches."""

        for class_obj in _RequestRegistry.registry:
            try:
                return class_obj(method, path, query, headers, body)
            except ValidationError:
                pass

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

    def validate(self):
        """Take a quick look at the request and decide whether it can be handled
        or not. Should raise ValidationError if this is not the case."""
        raise NotImplementedError()

    def inspect(self, client):
        """Take a deeper look at the request and check if the given client may do
        what is requested. Raising a instance of RequestError here immediately
        causes an error response being sent to the client.

        Return a instance of DummyResponse to directly provide a response to the
        client without contacting Elasticsearch.
        """
        raise NotImplementedError()


# Dynamically import all sub-modules to avoid manually adjusting
# this file every time we'll support an additional request
for module in os.listdir(os.path.dirname(__file__)):
    if module != '__init__.py' and module.endswith('.py'):
        __import__('elasticarmor.request.' + module[:-3])
