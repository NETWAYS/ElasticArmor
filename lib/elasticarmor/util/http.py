# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import httplib
import urlparse
import cStringIO

from requests.structures import CaseInsensitiveDict

__all__ = ['is_false', 'parse_query', 'HttpHeaders']


def is_false(value):
    """Return whether the given value represents a false query parameter."""
    return value.strip().lower() in ['false', '0', 'no', 'off']


def parse_query(query):
    """Parse the given query string and return it as dictionary."""
    return dict((name, [] if len(values) == 1 and is_false(values[0]) else values)
                for name, values in urlparse.parse_qs(query, keep_blank_values=True).iteritems())


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

    def extract_connection_options(self):
        """Remove and return all connection specific options as case insensitive dictionary.
        The Keep-Alive header is already parsed and its values registered as dictionary."""
        options = CaseInsensitiveDict()
        for option in self.getheaders('Connection'):
            if option in self:
                if option.lower() == 'keep-alive':
                    options[option] = dict(tuple(v.strip() for v in value.split('='))
                                           for value in self.getheaders(option))
                else:
                    options[option] = self[option]

                del self[option]
            elif option.lower() == 'keep-alive':
                options[option] = None
            elif option.lower() == 'close':
                options[option] = None

        if options:
            del self['Connection']

        return options

    @classmethod
    def from_http_header_dict(cls, http_header_dict):
        """Create and return a new instance of HttpHeaders based on the given HTTPHeaderDict object.
        HTTPHeaderDict is a class provided by module requests.packages.urllib3._collections."""
        file_like = cStringIO.StringIO()
        for name, value in http_header_dict.iteritems():  # iteritems() already yields multiple values separately!
            file_like.write('{0}: {1}\r\n'.format(name, value))

        file_like.write('\r\n')  # HTTP headers need to be terminated by a single CRLF

        try:
            file_like.seek(0)  # Rewind the cursor as we want to start reading the headers from the very beginning
            return cls(file_like, 0)
        finally:
            file_like.close()
