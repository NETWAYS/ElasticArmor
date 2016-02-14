# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import base64
import socket
import ssl
import sys
import threading
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from urlparse import urlparse

from ldap import LDAPError
from requests import RequestException

from elasticarmor import *
from elasticarmor.request import ElasticRequest, RequestError
from elasticarmor.settings import Settings
from elasticarmor.util import format_ldap_error
from elasticarmor.util.auth import Client
from elasticarmor.util.http import parse_query, HttpHeaders, HttpContext
from elasticarmor.util.mixins import LoggingAware

CONNECTION_TIMEOUT = 5  # Seconds
CONNECTION_REQUEST_LIMIT = 100
DENSE_ERROR_FORMAT = '{"error":"%(explain)s","status":%(code)d}'
PRETTY_ERROR_FORMAT = '''{
  "error" : "%(explain)s",
  "status" : %(code)d
}
'''


class ElasticReverseProxy(LoggingAware, ThreadingMixIn, HTTPServer):
    def __init__(self):
        settings = Settings()
        self.allow_from = settings.allow_from
        self.group_backend = settings.group_backend
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
        self._options = None
        self._client = None
        self._body = None

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
        except RequestException as error:
            self.log.error('An error occurred while communicating with Elasticsearch: %s', error)
            self.send_error(502, explain='An error occurred while communicating with Elasticsearch.'
                                         ' Please contact an administrator.')
        except:
            try:
                body = self.body
            except socket.timeout:
                body = None

            self.log.error('Unhandled exception occurred while handling request "%s" from %s:'
                           '\nHeaders:\n%s\nBody:\n%s\n', self.requestline, client_address,
                           self.headers, self.body, exc_info=True)
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

        # TODO: Chunked Transfer Coding (http://tools.ietf.org/html/rfc7230#section-4.1)

        content_length = 0
        if self.headers and self.command != 'HEAD':
            content_length = int(self.headers.get('Content-Length', 0))

        if content_length > 0:
            self.log.debug('Fetching request payload of length %u...', content_length)
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

                    if self.server.group_backend is not None:
                        try:
                            self._client.groups = self.server.group_backend.get_group_memberships(username)
                        except LDAPError as error:
                            self.log.error('Failed to fetch ldap group memberships for user "%s". %s.',
                                           username, format_ldap_error(error))
                    else:
                        self._client.groups = []

        return self._client

    def log_message(self, fmt, *args):
        pass  # We're logging requests by ourselves, thus we'll ignore BaseHTTPRequestHandler's builtin messages

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

        self.send_response(code, message)
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

    def fetch_request(self):
        self.raw_requestline = self.rfile.readline()  # Extract the first header line, required by parse_request()
        if not self.raw_requestline:
            self.log.debug('No request line received. Closing connection. (This is'
                           ' likely because the client has closed the connection!)')
            self.close_connection = True
            return
        elif not self.parse_request():
            self.log.debug('Invalid request received. Closing connection.')
            return

        self._context = HttpContext(self)
        if not self._context.has_proper_framing():
            self.send_error(400, explain='Bad or malicious message framing detected.')
            return

        if self.is_debugging():
            self.log.debug('Received request line "%s".', self.raw_requestline.rstrip())
            for name, value in self.headers.items():
                self.log.debug('Received header "%s: %s".', name, value)

        self._received_requests += 1
        if self._received_requests == CONNECTION_REQUEST_LIMIT:
            self.log.debug('Client "%s" reached request limit of %u. Connection is about to be closed.',
                           self.client, CONNECTION_REQUEST_LIMIT)
            self.close_connection = True

        # TODO: http://tools.ietf.org/html/rfc7230#section-3.2.4 (Second paragraph)

        url_parts = urlparse(self.path)
        path = url_parts.path.rstrip(' /')
        query = parse_query(url_parts.query)
        if query.get('pretty', False):
            # TODO: Elasticsearch responds also with YAML if desired by the client (format=yaml)
            self.error_message_format = PRETTY_ERROR_FORMAT

        if self.command != 'HEAD' and 'Transfer-Encoding' in self.headers and 'Content-Length' not in self.headers:
            self.send_error(411, explain='Requests with transfer coding are required to provide a content length.')
            return

        if not self.client.is_authenticated():
            # In case a client is not authenticated check if anonymous access is permitted
            allowed_ports = self.server.allow_from.get(self.client.address, [])
            if allowed_ports is not None and self.client.port not in allowed_ports:
                self.send_error(401, None, 'Authorization Required. Please authenticate yourself to access this realm.',
                                {'WWW-Authenticate': 'Basic realm="Elasticsearch - Protected by ElasticArmor"'})
                return
        elif self.client.groups is None:
            self.send_error(
                403, explain='Failed to fetch your group memberships. Please contact an administrator.')
            return

        self._options = self.headers.extract_connection_options()
        if self._options:
            self.log.debug('Extracted connection options: %s', self._options)

        request = ElasticRequest.create_request(self.command, path if path else '/', query, self.headers, self.body)
        if request is None:
            # TODO: Elasticsearch responds with text/plain, not application/json!
            self.send_error(400, explain='Unable to process this request. No request handler found.')
            return

        return request

    def handle_one_request(self):
        request = self.fetch_request()
        if request is None:
            return

        # Update the current context with the fetched request handler.
        # Might be of use for some handler and does not hurt if not..
        self._context.request = request

        # TODO: Fetch restrictions and register them on the client object for further processing

        try:
            response = request.inspect(self.client)
        except RequestError as error:
            self.send_error(error.status_code, explain=error.reason)
            return

        if response is None:
            response = self.server.elasticsearch.process(request)
            if response is None:
                self.send_error(504, explain='No response received from any of the configured Elasticsearch nodes.')
                return

        # Convert the response's header object so that we can use our own utilities. The original
        # object is overwritten to avoid a differentiation between it and the new one in the
        # context object. If this causes issues, feel free to refactor it.
        response.headers = HttpHeaders.from_http_header_dict(response.headers)
        response.headers.extract_connection_options()

        self._context.response = response  # Now that we got a response, we can update the context
        if not self._context.has_proper_framing():
            self.send_error(502, explain='Bad or malicious message framing detected. Please contact an administrator.')
            return

        # TODO: Via? (http://tools.ietf.org/html/rfc7230#section-5.7.1)
        self.send_response(response.status_code, response.reason)
        for name, value in response.headers.items():
            self.send_header(name, value)

        if self.close_connection:
            self.send_header('Connection', 'close')
        elif self._received_requests == 1:
            self.send_header('Keep-Alive', self.keep_alive_hint)
            self.send_header('Connection', 'keep-alive')  # Should be the last sent header, always

        self.end_headers()
        if response.content:
            self.log.debug('Sending response payload of length %s...', headers['Content-Length'])
            self.wfile.write(response.content)

        self.log.info('Forwarded response from Elasticsearch for request "%s %s" to client "%s".',
                      self.command, self.path, self.client)

    def finish(self):
        # TODO: http://tools.ietf.org/html/rfc7230#section-6.6 (The last three paragraphs)
        BaseHTTPRequestHandler.finish(self)
        self.server.elasticsearch.check_reachability()
