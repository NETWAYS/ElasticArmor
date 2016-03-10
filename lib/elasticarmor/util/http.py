# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import httplib
import urlparse
import cStringIO

from requests.structures import CaseInsensitiveDict

__all__ = ['is_false', 'parse_query', 'prepare_chunk', 'close_chunks', 'trailer_chunks',
           'read_chunked_content', 'ChunkParserError', 'RequestEntityTooLarge',
           'HttpHeaders', 'HttpContext']

CRLF = '\r\n'


def is_false(value):
    """Return whether the given value represents a false query parameter."""
    return value.strip().lower() in ['false', '0', 'no', 'off']


def parse_query(query):
    """Parse the given query string and return it as dictionary."""
    return dict((name, [] if len(values) == 1 and is_false(values[0]) else values)
                for name, values in urlparse.parse_qs(query, keep_blank_values=True).iteritems())


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

    Provides some utilities to check a message's integrity, validity and state."""

    def __init__(self, server, request, response=None):
        self.server = server
        self.request = request
        self.response = response

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
