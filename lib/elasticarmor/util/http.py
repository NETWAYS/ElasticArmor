# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import httplib
import urllib
import urlparse
import cStringIO

try:
    # Python 2.7+
    from collections import OrderedDict
except ImportError:
    # Python 2.6
    from simplejson import OrderedDict

from requests.structures import CaseInsensitiveDict

__all__ = ['prepare_chunk', 'close_chunks', 'trailer_chunks', 'read_chunked_content', 'ChunkParserError',
           'RequestEntityTooLarge', 'HttpHeaders', 'HttpContext', 'WsgiErrorLog', 'Query']

CRLF = '\r\n'


def prepare_chunk(data):
    """Prepare the given data to be sent as chunk and return the result."""
    return hex(len(data))[2:] + CRLF + data + CRLF


def close_chunks(trailers={}):
    """Return the bytes to close a chunked transmission."""
    return '0' + CRLF + trailer_chunks(trailers) + CRLF


def trailer_chunks(trailers):
    """Prepare the given chunk trailers and return the result."""
    return CRLF.join('{0}: {1}'.format(k, v) for k, v in trailers.iteritems())


def read_chunked_content(in_file, limit=None):
    """Read from the given file-like object until no chunked content is left and return it."""
    content = ''
    while True:
        chunk_size = in_file.readline()
        if chunk_size:
            try:
                size = int(chunk_size.strip().split(';')[0], 16)
            except ValueError:
                raise ChunkParserError('Got invalid chunk-size "{0!r}"'.format(chunk_size))

            if limit and len(content) + size > limit:
                raise RequestEntityTooLarge('Content length limit of {0} bytes exceeded'.format(limit))

            data = in_file.read(size)
            if len(data) == size:
                if size == 0:
                    break

                content += data
                crlf = in_file.readline()
                if crlf not in CRLF:
                    raise ChunkParserError('Expected CRLF. Got {0!r} instead.'.format(crlf))
            else:
                raise ChunkParserError('Got incomplete chunk. ({0:d} != {1:d})'.format(len(data), size))
        else:
            raise ChunkParserError('Expected chunk-size. Got nothing.')

    trailer_line = in_file.readline()
    while trailer_line not in CRLF:
        trailer_line = in_file.readline()
        # Discard any trailers, we cannot handle them anyway..

    return content


class ChunkParserError(Exception):
    """Raised by function read_chunked_content() in case of a parsing error."""
    pass


class RequestEntityTooLarge(Exception):
    """Raised by function read_chunked_content() in case the buffer size limit has been exceeded."""
    pass


class HttpHeaders(httplib.HTTPMessage):
    """HttpHeaders parser and container.

    This is a even more customized version of mimetools.Message than httplib.HTTPMessage. While the former is not
    able to properly handle header fields which appear multiple times the latter does but does not try to conform
    with its super class' interface.

    This class is currently only able to mimic the old behaviour of the method getheader and similar ones as it was
    the only requirement at the time it was written. To maintain httplib.HTTPMessage's functionality, the method
    getheaders has been overwritten.

    Further, the class provides one additional method called extract_connection_options which can be used to remove
    all connection specific headers and one additional class method to transform header objects returned by the
    module requests.
    """

    def __init__(self, fp=None, seekable=1):
        empty = fp is None
        if empty:
            fp = cStringIO.StringIO(CRLF)

        try:
            httplib.HTTPMessage.__init__(self, fp, seekable)
        finally:
            if empty:
                fp.close()

    def __getitem__(self, name):
        """Return the value of the given header or raise KeyError if the header does not exist.
        This returns only the last read header value in case multiple values exist."""
        value = httplib.HTTPMessage.__getitem__(self, name)
        if ', ' in value:
            value = value.split(', ')[-1]

        return value

    def get(self, name, default=None):
        """Alias for method getheader."""
        return self.getheader(name, default)

    def getheader(self, name, default=None):
        """Return the value of the given header or the default if the header does not exist.
        This returns only the last read header value in case multiple values exist."""
        value = httplib.HTTPMessage.getheader(self, name, default)
        if isinstance(value, basestring) and ', ' in value:
            value = value.split(', ')[-1]

        return value

    def getheaders(self, name):
        """Return all values of the given header or an empty list if the header does not exist."""
        value = httplib.HTTPMessage.getheader(self, name)
        if value is not None:
            return value.split(', ')

        return []

    def isheader(self, line):
        """Determine whether a given line is a legal header.

        Properly complies with http://tools.ietf.org/html/rfc7230#section-3.2.4 regarding whitespace."""

        colon_position = line.find(':')
        if colon_position > 0:
            header_name = line[:colon_position]
            if header_name.strip() == header_name:
                return header_name.lower()

    def addcontinue(self, key, more):
        """Add more field data from a continuation line.

        Properly complies with http://tools.ietf.org/html/rfc7230#section-3.2.4 regarding line folding."""

        prev = self.dict[key]
        self.dict[key] = prev + ' ' + more

    def extract_connection_options(self):
        """Remove and return all connection specific options as case insensitive dictionary.

        Header fields being handled:
        - Connection
        - Host
        - Trailer
        - Transfer-Encoding
        - Proxy-Authenticate
        - Proxy-Authorization

        Keep-Alive is returned as dictionary and all others as list or None.

        """
        options = CaseInsensitiveDict()
        for option in self.getheaders('Connection'):
            if option in self:
                if option.lower() == 'keep-alive':
                    options[option] = dict(tuple(v.strip() for v in value.split('='))
                                           for value in self.getheaders(option))
                else:
                    options[option] = [v.strip().lower() for v in self.getheaders(option)]

                del self[option]
            elif option.lower() == 'keep-alive':
                options[option] = None
            elif option.lower() == 'close':
                options[option] = None

        if options:
            del self['Connection']

        headers = ['Host', 'Trailer', 'Transfer-Encoding', 'Proxy-Authenticate', 'Proxy-Authorization']
        for header_name in (h for h in headers if h in self):
            options[header_name] = [v.strip().lower() for v in self.getheaders(header_name)]
            del self[header_name]

        return options

    def extend_via_field(self, received_protocol, received_by, comment=None):
        """Register the given Via field values without losing any existing ones."""
        formatted_values = '{0} {1}{2}'.format(received_protocol, received_by, ' ' + comment if comment else '')

        intermediaries = self.get('Via', '')
        if intermediaries:
            self['Via'] = ', '.join((intermediaries, formatted_values))
        else:
            self['Via'] = formatted_values

    @classmethod
    def from_http_header_dict(cls, http_header_dict):
        """Create and return a new instance of HttpHeaders based on the given HTTPHeaderDict object.
        HTTPHeaderDict is a class provided by module requests.packages.urllib3._collections."""
        file_like = cStringIO.StringIO()
        for name, value in http_header_dict.iteritems():  # iteritems() already yields multiple values separately!
            file_like.write('{0}: {1}{2}'.format(name.strip(), value, CRLF))

        file_like.write(CRLF)  # HTTP headers need to be terminated by a single CRLF

        try:
            file_like.seek(0)  # Rewind the cursor as we want to start reading the headers from the very beginning
            return cls(file_like, 0)
        finally:
            file_like.close()


class HttpContext(object):
    """HttpContext container. It consists of the server, the request and an optional response.

    Provides also some utilities to e.g. check a message's integrity, validity and state."""

    def __init__(self, server, request, response=None):
        self.server = server
        self.request = request
        self.response = response

    @property
    def forwarded_for(self):
        """The IP-address and port of the host which is the actual origin of the request."""
        ip = port = None
        if 'x-forward-for' in self.request.headers:
            # Required for compatibility reasons with Kibana 4.1.x.
            # See https://github.com/elastic/kibana/issues/4609 for more details
            ip = self.request.headers.getheaders('x-forward-for')[0].strip()
        elif 'x-forwarded-for' in self.request.headers:
            ip = self.request.headers.getheaders('x-forwarded-for')[0].strip()
        elif 'forwarded' in self.request.headers:
            pass  # TODO: https://tools.ietf.org/html/rfc7239#section-4

        if not ip or ip == 'unknown' or ip.startswith('_'):
            return None, None

        return ip, port

    def create_wsgi_environ(self):
        """Create and return a WSGI compliant environment."""
        environ = self.server.wsgi_environ.copy()
        environ['REQUEST_METHOD'] = self.request.command
        environ['SCRIPT_NAME'] = ''
        path, _, query = self.request.path.partition('?')
        environ['PATH_INFO'] = path
        environ['QUERY_STRING'] = query
        environ['SERVER_PROTOCOL'] = self.request.request_version
        environ['REMOTE_ADDR'] = self.request.client_address[0]
        environ['REMOTE_HOST'] = self.request.client_address[0]
        environ['REMOTE_PORT'] = self.request.client_address[1]
        environ['wsgi.input'] = cStringIO.StringIO(self.request.body)  # TODO: Adjust this once body is a generator
        environ.update(('HTTP_' + name.upper().replace('-', '_'), value)
                       for name, value in self.request.headers.items())

        if self.request.client.username:
            environ['REMOTE_USER'] = self.request.client.username
        if 'Content-Type' in self.request.headers:
            environ['CONTENT_TYPE'] = self.request.headers.getheader('Content-Type')
        if 'Content-Length' in self.request.headers:
            environ['CONTENT_LENGTH'] = self.request.headers.getheader('Content-Length')

        return environ

    def has_proper_framing(self):
        """Return whether a message's framing is valid.

        See http://tools.ietf.org/html/rfc7230#section-3.3.3 articles 3 and 4 for an explanation."""

        if self.response is None:
            headers = self.request.headers
            options = self.request.options
        else:
            headers = self.response.headers
            options = self.response.options

        content_length_found = False
        if 'Content-Length' in headers:
            content_length_found = True

            try:
                content_length = int(headers['Content-Length'])
                if content_length < 0 or any(int(v) != content_length for v in headers.getheaders('Content-Length')):
                    return False
            except ValueError:
                return False

        if options is not None and 'Transfer-Encoding' in options:
            if content_length_found or (
                    self.response is None and options['Transfer-Encoding'][-1] != 'chunked'):
                return False

        return True

    def has_chunked_payload(self):
        """Return whether a message has a chunked payload attached to it.

        See http://tools.ietf.org/html/rfc7230#section-3.3.1 paragraph 6 for an explanation."""

        if self.response is None:
            return self.request.options is not None and \
                   self.request.options.get('Transfer-Encoding', [None])[-1] == 'chunked'

        if self.request.command != 'HEAD' and not (self.request.command == 'GET' and self.response.status_code == 304):
            return self.response.options is not None and \
                   self.response.options.get('Transfer-Encoding', [None])[-1] == 'chunked'

        return False


class WsgiErrorLog(object):
    """WsgiErrorLog is a file-like object compliant to PEP 333 that
    may be used as error log passed to a WSGI application object."""

    def __init__(self, logger):
        self.logger = logger

    def flush(self):
        """Flush the internal buffer. This is a no-op."""
        pass

    def write(self, message):
        """Write a error message to the log. There is no return value."""
        self.logger.error(message.rstrip())

    def writelines(self, messages):
        """Write a sequence of error messages to the log. The sequence can be any iterable
        object producing strings, typically a list of strings. There is no return value.

        """
        for message in messages:
            self.write(message)


class Query(OrderedDict):
    def discard(self, *params):
        """Discard the given parameters from this query, if present."""
        for param in params:
            try:
                del self[param]
            except KeyError:
                pass

    def last(self, param, default=None):
        """Return the very last value of the given parameter,
        or the default if the parameter does not exist.

        """
        try:
            return self[param][-1]
        except KeyError:
            return default

    def is_false(self, param, default=True):
        """Return whether the given parameter represents a false
        value, or the default if the parameter does not exist.

        """
        try:
            return self[param][-1].strip().lower() in ['false', '0', 'no', 'off']
        except KeyError:
            return default

    @classmethod
    def from_query_string(cls, query_string):
        """Parse the given query string and return a new instance of Query."""
        query = cls()
        for name, value in ((n, urllib.unquote(v))
                            for n, v in urlparse.parse_qsl(query_string, keep_blank_values=True)):
            query.setdefault(name, []).append(value)

        return query
