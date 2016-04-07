# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import os
import re
from functools import update_wrapper

try:
    # Python 2.7+
    from collections import OrderedDict
    import json
except ImportError:
    # Python 2.6
    from ordereddict import OrderedDict
    import simplejson as json

from elasticarmor.util.http import HttpHeaders
from elasticarmor.util.mixins import LoggingAware

__all__ = ['RequestError', 'PermissionError', 'Permission', 'Permissions', 'ElasticResponse', 'ElasticRequest']


class _RequestRegistry(type):
    """Metaclass to register every class derived from ElasticRequest."""

    registry = []
    type_map = {}

    def __new__(mcs, class_name, base_classes, namespace):
        class_obj = super(_RequestRegistry, mcs).__new__(mcs, class_name, base_classes, namespace)
        if class_name != 'ElasticRequest':
            mcs.registry.append(class_obj)
            mcs.type_map[class_obj.__name__] = class_obj

            for command, locations in class_obj.locations.items():
                if not isinstance(locations, list):
                    locations = [locations]

                class_obj.locations[command] = [re.compile('^' + location.format(**class_obj.macros) + '/?$')
                                                for location in locations]

        return class_obj

    @classmethod
    def sort(cls):
        """Sort the handler registry."""
        cls.registry.sort(key=cls._get_priority, reverse=True)
        cls.type_map.clear()  # Free some memory, the registry is only sorted once

    @classmethod
    def _get_priority(cls, handler):
        """Return and set the given handler's priority."""
        if handler.priority is None:
            try:
                if handler.before is not None:
                    handler.priority = cls._get_priority(cls.type_map[handler.before]) + 1
                elif handler.after is not None:
                    handler.priority = cls._get_priority(cls.type_map[handler.after]) - 1
                else:
                    handler.priority = 0
            except KeyError:
                raise AssertionError('Request handler {0} of module {1} defines an invalid dependency: {2}'
                                     ''.format(handler.__name__, handler.__module__, handler.before or handler.after))

        return handler.priority


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
    In case the client lacks a given permission, PermissionError is raised indicating the missing permissions.

    The basic usage is as follows:

        @Permission('<permission-name>')
        def inspect(self, client):
            pass

        @Permissions('<permission-name>', '<permission-name>')
        def inspect(self, client):
            pass

    Permission checks are context-aware by using the names of the default (singular) location macros to access
    the index, document-type and field that is possibly part of the request's path. In case your locations do
    not use the default macros, pass the name of the macro as the respective keyword argument to this decorator:

        @Permission('<permission-name>', index='<macro-name>')
        def inspect(self, client):
            pass

        @Permissions('<permission-name>', '<permission-name>', document_type='<macro-name>')
        def inspect(self, client):
            pass

    If you want to limit the context-awareness to a particular scope, pass its identifier as keyword argument:

        @Permission('<permission-name>', scope='cluster')
        def inspect(self, client):
            pass

    Consider to stack multiple decorators if you have permissions that require different scopes:

        @Permission('<permission-name>', scope='indices')
        @Permission('<permission-name>')
        def inspect(self, client):
            pass
    """

    def __init__(self, permission, *permissions, **context_attributes):
        self.permissions = list(permissions)
        self.permissions.insert(0, permission)
        self.scope = context_attributes.get('scope')
        self.index_attribute = context_attributes.get('index', 'index')
        self.type_attribute = context_attributes.get('document_type', 'document')
        self.field_attribute = context_attributes.get('field', 'field')

    def __call__(self, inspector):
        def protector(request, client):
            context = {}
            if not self.scope or self.scope != 'cluster':
                context['index'] = getattr(request, self.index_attribute, None)
            if not self.scope or self.scope not in ['cluster', 'indices']:
                context['document_type'] = getattr(request, self.type_attribute, None)
            if not self.scope or self.scope == 'fields':
                context['field'] = getattr(request, self.field_attribute, None)

            missing = [p for p in self.permissions if not client.can(p, **context)]
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
            iterator = iter(self.content.splitlines(True))  # keepends=True
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

    macros = {
        'index': '(?P<index>(?!_|-|\+)[^*,/]+)',
        'indices': '(?P<indices>(?!_)[^/]+|_all)',
        'document': '(?P<document>(?!_|-|\+)[^*,/]+)',
        'documents': '(?P<documents>(?!_)[^/]+|_all)',
        'identifier': '(?P<identifier>(?!-|\+)[^,/]+)',
        'identifiers': '(?P<identifiers>[^/]+)',
        'name': '(?P<name>(?!_|-|\+)[^*,/]+)',
        'names': '(?P<names>(?!_)[^/]+)',
        'keyword': '(?P<keyword>(?!-|\+)[^*,/]+)',
        'keywords': '(?P<keywords>[^/]+)',
        'field': '(?P<field>(?!-|\+)[^*,/]+)',
        'fields': '(?P<fields>[^/]+)',
        'es': '(?:es)?',
        's': 's?'
    }

    # The priority of a request handler. The higher the value, the earlier a request handler is asked to process a
    # request. If you're not competing with other handlers or a dynamic dependency is sufficient, leave the default
    priority = None

    # Set one of the following to the name of the class your handler should be processed
    # before or after. This will not have any effect in case a priority is already set
    before = None
    after = None

    # The base url a request handler is responsible for. If this is not None, the base
    # implementation of is_valid() checks whether a request's path starts with this url
    base_url = None

    # The locations grouped by commands a request handler is responsible for. Each key is a HTTP command such
    # as 'GET' and holds a single regular expression or a list of multiple regular expressions of type string.
    # Regular expressions may be automatically populated with certain macros. Please see the macros class
    # attribute for a list of available macros. To utilize a macro, put {<macro>} into your expression. In
    # case of a successful match the base implementation of is_valid sets the _match instance attribute with
    # which you can access e.g. captured groups. Note that some macros are available as group using their name.
    locations = {}

    def __init__(self, context, **kwargs):
        super(ElasticRequest, self).__init__()
        self._match = None
        self._json = False

        self.context = context
        for name, value in kwargs.iteritems():
            setattr(self, name, value)

    def __getattr__(self, name):
        """Access the given attribute on the context's request or the group of the matched
        location and return its value. Raises AttributeError if the attribute is not found.

        """
        try:
            value = getattr(self.context.request, name)
        except AttributeError as error:
            try:
                value = self._match.groupdict()[name]
            except (AttributeError, KeyError):
                raise error

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
        assert self.base_url is not None, 'Class {0} of module {1} does not define a base url' \
                                           ''.format(self.__class__.__name__, self.__class__.__module__)

        environ = self.context.create_wsgi_environ()
        environ['SCRIPT_NAME'] = self.base_url
        environ['SCRIPT_FILENAME'] = self.path
        environ['PATH_INFO'] = self.path[len(self.base_url):]
        return environ

    @property
    def json(self):
        if self._json is False:
            self._json = None
            data = self.body
            if not data and 'source' in self.query:
                data = self.query['source'][-1]

            if data:
                try:
                    self._json = self.json_decode(data)
                except ValueError as error:
                    raise RequestError(400, 'Failed to parse payload. An error occurred: {0}'.format(error))

        return self._json

    def json_decode(self, data):
        """Decode the given JSON data and return the result."""
        return json.loads(data, object_pairs_hook=OrderedDict)

    def json_encode(self, data, pretty=False):
        """Return the given data encoded to JSON."""
        if not pretty:
            return json.dumps(data, separators=(',', ':'))

        return json.dumps(data, indent=2, separators=(',', ' : '))

    def get_match(self, name, default=None):
        """Return the given group of the matched location or the default if no such group exists."""
        return self._match.groupdict().get(name, default)

    def is_valid(self):
        """Take a quick look at the request and return whether it can be handled or not."""
        if self.base_url is not None:
            return self.path.startswith(self.base_url)

        assert self.locations, 'Class {0} of module {1} neither defines a base url nor any locations and does not' \
                               ' override method is_valid'.format(self.__class__.__name__, self.__class__.__module__)

        try:
            locations = self.locations[self.command]
        except KeyError:
            return False

        match = next((p for p in (pattern.match(self.path) for pattern in locations) if p is not None), None)
        if match is None:
            return False

        self._match = match
        return True

    def inspect(self, client):
        """Take a deeper look at the request and check if the given client may do
        what is requested. Raising a instance of RequestError here immediately
        causes an error response being sent to the client.

        Return a instance of ElasticResponse to directly provide a response to the
        client without contacting Elasticsearch.

        """
        raise NotImplementedError('Class {0} of module {1} does not overwrite method inspect'
                                  ''.format(self.__class__.__name__, self.__class__.__module__))

    def prepare_transformation(self, response):
        """Prepare any required transformations for the given response and
        return a reason if a transformation is about to be applied on it.

        """
        pass

    def transform(self, stream, chunk_size):
        """Apply required transformations on the given response-body stream and return a new iterable."""
        return stream


# Dynamically import all sub-modules to avoid manually adjusting
# this file every time we'll support an additional request
for module in os.listdir(os.path.dirname(__file__)):
    if module != '__init__.py' and module.endswith('.py'):
        __import__('elasticarmor.request.' + module[:-3])

# Once all handlers are registered, sort them based on their priority. This needs
# to be done at the very end to resolve dynamic dependencies between handlers
_RequestRegistry.sort()
