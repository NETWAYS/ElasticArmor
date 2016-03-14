# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import os
import json
from functools import update_wrapper

from elasticarmor.util.http import HttpHeaders
from elasticarmor.util.mixins import LoggingAware

__all__ = ['RequestError', 'PermissionError', 'Permission', 'Permissions', 'ElasticResponse', 'ElasticRequest']


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


class Permission(object):
    """Decorator for method inspect of class ElasticRequest to check a client's permission.

    The basic usage is as follows:

        @Permission('<permission-name>')
        def inspect(self, client):
            pass

        @Permissions('<permission-name>', '<permission-name>')
        def inspect(self, client):
            pass

    In case the client lacks a given permission, PermissionError is raised indicating the missing permissions.
    """

    def __init__(self, permission, *permissions):
        self.permissions = list(permissions)
        self.permissions.insert(0, permission)

    def __call__(self, inspector):
        def protector(request, client):
            missing = [p for p in self.permissions if not client.can(p)]
            if missing:
                raise PermissionError('You are missing the following permissions: {0}'.format(', '.join(missing)))
            else:
                return inspector(request, client)

        return update_wrapper(protector, inspector)
Permissions = Permission


class ElasticResponse(object):
    """Response object which may be provided by instances of ElasticRequest.

    Any instance of ElasticRequest might return this to indicate that
    Elasticsearch does not need to be contacted to provide a response
    to the client.
    """

    def __init__(self):
        self._streaming = False

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

    def wsgi_response(self, status_line, headers, exc_info=None):
        """Populate this response by parsing the given status line and headers.
        This method solely exists to be passed to a WSGI application object.

        """
        if exc_info is not None:
            try:
                if self._streaming:
                    raise exc_info[0], exc_info[1], exc_info[2]
            finally:
                exc_info = None
        elif self.status_code is not None:
            raise AssertionError('The response has already been populated')

        status_code, reason = status_line.split(' ', 1)
        self.status_code = int(status_code)
        self.reason = reason

        self.headers = HttpHeaders()
        for header_name, header_value in headers:
            self.headers[header_name] = header_value

        if self.headers.extract_connection_options():
            raise AssertionError('Application supplied hop-by-hop headers')

    def stream(self, chunk_size, decode_content):
        """Return the payload as chunks by optionally respecting the given size-hint. Argument
        decode_content is required to ensure compatibility with requests.Response and is ignored.

        """
        if callable(self.content):
            iterator = iter(self.content(chunk_size))
        elif isinstance(self.content, basestring):
            iterator = iter(self.content.splitlines(keepends=True))
        else:
            iterator = iter(self.content)

        while True:
            yield next(iterator)
            self._streaming = True


class ElasticRequest(LoggingAware, object):
    """Base class for all Elasticsearch request handlers.

    Every derived class placed in this sub-module is automatically being imported and used.
    """
    __metaclass__ = _RequestRegistry

    # The priority of a request handler. The higher the value, the earlier a request handler is
    # asked to process a request. If you're not competing with other handlers, leave the default
    priority = 0

    # The base url a request handler is responsible for. The base implementation
    # of is_valid() checks whether a request's path starts with this url
    base_url = None

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
    def wsgi_environ(self):
        environ = self.context.create_wsgi_environ()
        environ['SCRIPT_NAME'] = self.base_url
        environ['SCRIPT_FILENAME'] = self.path
        environ['PATH_INFO'] = self.path[len(self.base_url):]
        return environ

    @property
    def json(self):
        if self._json is None:
            self._json = json.loads(self.body)

        return self._json

    def is_valid(self):
        """Take a quick look at the request and return whether it can be handled or not."""
        return self.base_url is not None and self.path.startswith(self.base_url)

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
