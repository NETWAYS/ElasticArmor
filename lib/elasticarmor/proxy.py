# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import base64
import socket
import ssl
import sys
import threading
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from urlparse import urlparse

from requests import RequestException

from elasticarmor import *
from elasticarmor.request import ElasticRequest, RequestError
from elasticarmor.settings import Settings
from elasticarmor.util import format_elasticsearch_error
from elasticarmor.util.auth import AuthorizationError, Auth, Client
from elasticarmor.util.http import *
from elasticarmor.util.mixins import LoggingAware

# TODO: Make all constants but the format strings configurable
CONNECTION_TIMEOUT = 5  # Seconds
CONNECTION_REQUEST_LIMIT = 100
CONTENT_BUFFER_SIZE = 2**16  # Bytes, 64KiB
MAX_CHUNK_SIZE = 4096  # Bytes, used when transferring response payloads
DENSE_ERROR_FORMAT = '{"error":"%(explain)s","status":%(code)d}'
PRETTY_ERROR_FORMAT = '''{
  "error" : "%(explain)s",
  "status" : %(code)d
}
'''


class ElasticReverseProxy(LoggingAware, ThreadingMixIn, HTTPServer):
    def __init__(self):
        settings = Settings()
        self.auth = Auth(settings)
        self.elasticsearch = settings.elasticsearch

        HTTPServer.__init__(self, (settings.listen_address, settings.listen_port),
                            ElasticRequestHandler, bind_and_activate=False)
        if settings.secure_connection:
            self.socket = ssl.wrap_socket(self.socket, settings.private_key, settings.certificate,
                                          server_side=True, ssl_version=ssl.PROTOCOL_TLSv1)

    def launch(self):
        self.server_bind()
        self.log.debug('Bound TCP socket to "%s"...', self.server_address[0])
        self.server_activate()
        self.log.debug('Now listening on port %d...', self.server_port)
        self.log.debug('Starting to serve incoming requests...')
        self.serve_forever()

    def process_request(self, request, client_address):
        self.log.debug('Accepted request from "%s:%u".', *client_address)
        thread = threading.Thread(target=self.process_request_thread, args=(request, client_address))
        thread.setDaemon(1)  # Required because UnixDaemon utilizes atexit for cleanup purposes
        thread.request_thread = True  # Required to simplify identification when cleaning up
        thread.start()
        self.log.debug('Started thread %s to process request from "%s:%u".', thread.name, *client_address)

    def shutdown(self):
        self.log.debug('Stopping to serve incoming requests...')
        HTTPServer.shutdown(self)

        for thread in threading.enumerate():
            try:
                if thread.request_thread:
                    self.log.debug('Waiting for request thread %s to finish...', thread.name)
                    thread.join()
            except AttributeError:
                pass

        self.server_close()
        self.log.debug('Closed socket.')


class ElasticRequestHandler(LoggingAware, BaseHTTPRequestHandler):
    keep_alive_hint = 'timeout={0}, max={1}'.format(CONNECTION_TIMEOUT, CONNECTION_REQUEST_LIMIT)
    server_version = APP_NAME + '/' + VERSION
    error_message_format = DENSE_ERROR_FORMAT
    error_content_type = 'application/json'
    protocol_version = 'HTTP/1.1'
    MessageClass = HttpHeaders

    def __init__(self, request, client_address, server):
        self._received_requests = 0
        self._context = None
        self._client = None
        self._body = None

        self.options = None

        # These attributes will be set by parse_request(). They're initialized here
        # to prevent my IDE from complaining and to simplify error handling..
        self.raw_requestline = None
        self.requestline = None
        self.headers = None
        self.command = None
        self.path = None

        # Set the timeout to use for the connection
        request.settimeout(CONNECTION_TIMEOUT)

        # The following is borrowed from SocketServer.BaseRequestHandler.__init__ to be able to handle exceptions.
        # Instead of overwriting SocketServer.BaseServer.handle_error we're doing this here because otherwise it's
        # not possible to utilize all the "shiny" HTTP utilities of BaseHTTPServer.BaseHTTPRequestHandler.
        self.client_address = client_address
        self.request = request
        self.server = server

        try:
            self.setup()
            self.handle()
        except socket.timeout:
            self.close_connection = True
            self.log.debug('Client "%s" timed out. Closing connection.', self.client)
            self.send_error(408, explain='Idle time limit exceeded. (%u Seconds)' % CONNECTION_TIMEOUT)
        except ChunkParserError as error:
            self.log.debug('Client "%s" sent an invalid chunked payload. Error: %s', self.client, error)
            self.send_error(400, explain='Payload encoding invalid. Error: {0}'.format(error))
        except RequestEntityTooLarge as error:
            self.log.debug('Client "%s" exceeded the buffer size limit. Closing connection.', self.client)
            self.close_connection = True
            self.send_error(413, explain=str(error))
        except RequestException as error:
            self.log.error('An error occurred while communicating with Elasticsearch: %s',
                           format_elasticsearch_error(error))
            self.send_error(502, explain='An error occurred while communicating with Elasticsearch.'
                                         ' Please contact an administrator.')
        except Exception:
            exc_info = sys.exc_info()  # Fetch exception information now..

            try:
                body = self.body
            except Exception:  # ..as it may refer to a different one later on
                body = None

            self.log.error('Unhandled exception occurred while handling request "%s" from %s:'
                           '\nHeaders:\n%s\nBody:\n%s\n', self.requestline, client_address,
                           self.headers, body, exc_info=exc_info)
            self.send_error(
                500, explain='An error occurred while processing this request. Please contact an administrator.')
        finally:
            try:
                self.finish()
            finally:
                sys.exc_traceback = None  # Help garbage collection

    @property
    def body(self):
        if self._body is not None:
            return self._body

        if self._context.has_chunked_payload():
            self.log.debug('Fetching streamed request payload...')
            self._body = read_chunked_content(self.rfile, CONTENT_BUFFER_SIZE)
            self.log.debug('Completed fetching payload of length %u.', len(self._body))
        else:
            content_length = 0
            if self.headers and self.command != 'HEAD':
                content_length = int(self.headers.get('Content-Length', 0))

            if content_length > 0:
                self.log.debug('Fetching request payload of length %u...', content_length)
                if content_length > CONTENT_BUFFER_SIZE:
                    raise RequestEntityTooLarge(
                        'Content length limit of {0} bytes exceeded'.format(CONTENT_BUFFER_SIZE))

                self._body = self.rfile.read(content_length)
            else:
                self.log.debug('Request payload is either empty or it\'s a HEAD request.')
                self._body = ''

        return self._body

    @property
    def client(self):
        if self._client is not None:
            return self._client

        self._client = Client(*self.client_address)

        try:
            header_value = self.headers['Authorization']
            user_auth = base64.b64decode(header_value.replace('Basic ', ''))
        except (KeyError, TypeError):
            pass
        else:
            if ':' in user_auth:
                username, password = user_auth.split(':', 1)
                if username and password:
                    self._client.username = username
                    self._client.password = password

        return self._client

    def send_header(self, keyword, value):
        BaseHTTPRequestHandler.send_header(self, keyword, value)
        self.log.debug('Sent header "%s: %s".', keyword, value)

    def send_error(self, code, message=None, explain=None, headers=None):
        # BaseHTTPRequestHandler's implementation of send_error suffers from various issues but the
        # most obvious one is flexibility, thus we're overwriting it here to accommodate this.
        if message is None or explain is None:
            try:
                default_message, default_explain = self.responses[code]
            except KeyError:
                default_message, default_explain = '???', '???'

            if message is None:
                message = default_message
            if explain is None:
                explain = default_explain

        self.log.debug('Starting error response with status code %u, status message "%s" and explain message "%s".',
                       code, message, explain)

        if code == 400:
            self.close_connection = True  # Bad guys don't deserve to be kept alive..
        elif not self.close_connection:
            try:
                # We need to fetch the request payload even if it's not necessary to handle
                # the request as the remaining data will most likely cause misbehaviour
                _ = self.body
            except Exception as error:  # Fetch the request payload no matter what..
                self.log.debug('Failed to fetch the remaining request payload. An error occurred: %s', error)
                self.close_connection = True  # ..but close the connection if it's not possible

        self.send_response(code, message)
        self.send_header('Server', self.version_string())
        self.send_header('Date', self.date_time_string())
        if headers:
            for name, value in headers.iteritems():
                self.send_header(name, value)

        content = self.error_message_format % {'code': code, 'message': message, 'explain': explain}
        self.send_header('Content-Type', self.error_content_type)
        self.send_header('Content-Length', len(content))

        if self.close_connection:
            self.send_header('Connection', 'close')
        elif self._received_requests == 1:
            self.send_header('Keep-Alive', self.keep_alive_hint)
            self.send_header('Connection', 'keep-alive')

        self.end_headers()

        if self.command != 'HEAD' and code >= 200 and code not in (204, 304):
            self.log.debug('Sending response payload of length %u...', len(content))
            self.wfile.write(content)

        if code != 408:  # 408 = Request timeout; This is not triggered by the client, so there is no need to log it
            self.log.info('Refused request "%s %s" issued by "%s" with status %u. Reason: %s (%s).',
                          self.command, self.path, self.client, code, message, explain)

    def send_response(self, code, message=None):
        # BaseHTTPRequestHandler's implementation of send_response is not entirely appropriate
        # for a proxy so we're overwriting it here to accomplish what we require.
        if message is None:
            try:
                message = self.responses[code][0]
            except KeyError:
                message = ''

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, code, message))

    def fetch_request(self):
        # Free some memory as we're not closing the connection and thus the thread is kept alive
        self._context = self._body = self.options = self.headers = self.command = self.path = None

        self.raw_requestline = self.rfile.readline()  # Extract the first header line, required by parse_request()
        if not self.raw_requestline:
            self.log.debug('No request line received. Closing connection. (This is'
                           ' likely because the client has closed the connection!)')
            self.close_connection = True
            return
        elif not self.parse_request():
            self.log.debug('Invalid request received. Closing connection.')
            return

        if self.headers.status in ('No headers', 'Non-header line where header expected'):
            # Since headers are completely optional, "No headers" is actually not an error per se but the
            # implementation of httplib.HTTPMessage.readheaders() emits this status only if the required
            # CRLF after the request line is missing hence we consider it as an error as well.
            self.send_error(400, explain='Invalid header syntax detected.')
            return

        if self.is_debugging():
            self.log.debug('Received request line "%s".', self.raw_requestline.rstrip())
            for name, value in self.headers.items():
                self.log.debug('Received header "%s: %s".', name, value)

        self.options = self.headers.extract_connection_options()
        if self.options:
            self.log.debug('Extracted connection options: %s', self.options)

        self._context = HttpContext(self)
        if not self._context.has_proper_framing():
            self.send_error(400, explain='Bad or malicious message framing detected.')
            return

        self._received_requests += 1
        if self._received_requests == CONNECTION_REQUEST_LIMIT:
            self.log.debug('Client "%s" reached request limit of %u. Connection is about to be closed.',
                           self.client, CONNECTION_REQUEST_LIMIT)
            self.close_connection = True

        url_parts = urlparse(self.path)
        path = url_parts.path.rstrip(' /')
        query = parse_query(url_parts.query)
        if query.get('pretty', False):
            # TODO: Elasticsearch responds also with YAML if desired by the client (format=yaml)
            self.error_message_format = PRETTY_ERROR_FORMAT

        if not self.client.authenticated and not self.server.auth.authenticate(self.client):
            self.send_error(401, None, 'Authorization Required. Please authenticate yourself to access this realm.',
                            {'WWW-Authenticate': 'Basic realm="Elasticsearch - Protected by ElasticArmor"'})
            return
        elif self.client.groups is None or self.client.roles is None:
            self.send_error(
                403, explain='Failed to fetch your group/role memberships. Please contact an administrator.')
            return
        elif not self.client.roles:
            self.send_error(403, explain='You\'re not permitted to access this realm.')
            return

        expectations = [v.lower() for v in self.headers.getheaders('Expect')]
        if expectations and ('100-continue' not in expectations or len(expectations) > 1):
            self.send_error(417)
            return
        elif self.request_version >= 'HTTP/1.1' and '100-continue' in expectations:
            self.send_response(100)
            del self.headers['Expect']
            self.log.debug('Answered to 100-continue expectation.')

        request = ElasticRequest.create_request(self.command, path if path else '/', query, self.headers, self.body)
        if request is None:
            # TODO: Elasticsearch responds with text/plain, not application/json!
            self.send_error(400, explain='Unable to process this request. No request handler found.')
            return

        request.options = self.options
        return request

    def handle_one_request(self):
        request = self.fetch_request()
        if request is None:
            return

        # Update the current context with the fetched request handler.
        # Might be of use for some handler and does not hurt if not..
        self._context.request = request

        try:
            response = request.inspect(self.client)
        except RequestError as error:
            self.send_error(error.status_code, explain=error.reason)
            return
        except AuthorizationError as error:
            self.log.error('Failed to authorize client "%s". An error occurred: %s', self.client, error)
            self.send_error(
                403, explain='An error occurred while checking your authorization. Please contact an administrator.')
            return

        if response is None:
            self.log.debug('Forwarding request "%s %s" to Elasticsearch...', self.command, self.path)
            request.headers.extend_via_field(self.protocol_version, APP_NAME)
            response = self.server.elasticsearch.process(request)
            if response is None:
                self.log.debug('No response received from any of the configured Elasticsearch nodes.')
                self.send_error(504, explain='No response received from any of the configured Elasticsearch nodes.')
                return

        # Convert the response's header object so that we can use our own utilities. The original
        # object is overwritten to avoid a differentiation between it and the new one in the
        # context object. If this causes issues, feel free to refactor it.
        response.headers = HttpHeaders.from_http_header_dict(response.headers)
        response.headers.extend_via_field(self.protocol_version, APP_NAME)
        response.options = response.headers.extract_connection_options()

        self._context.response = response  # Now that we got a response, we can update the context
        if not self._context.has_proper_framing():
            self.send_error(502, explain='Bad or malicious message framing detected. Please contact an administrator.')
            return

        self.send_response(response.status_code, response.reason)
        for name, value in response.headers.items():
            self.send_header(name, value)

        if self.close_connection:
            self.send_header('Connection', 'close')
        elif self._received_requests == 1:
            self.send_header('Keep-Alive', self.keep_alive_hint)
            self.send_header('Connection', 'keep-alive')  # Should be the last sent header, always

        self.end_headers()

        self.log.debug('Transferring response payload...')
        chunked_content = self._context.has_chunked_payload()
        for data in response.raw.stream(MAX_CHUNK_SIZE, decode_content=False):
            self.wfile.write(prepare_chunk(data) if chunked_content else data)
        else:
            if chunked_content:
                self.wfile.write(close_chunks())

        self.log.info('Forwarded response from Elasticsearch for request "%s %s" to client "%s".',
                      self.command, self.path, self.client)

    def finish(self):
        # TODO: http://tools.ietf.org/html/rfc7230#section-6.6 (The last three paragraphs)
        BaseHTTPRequestHandler.finish(self)
        self.server.elasticsearch.check_reachability()
