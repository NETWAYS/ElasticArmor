# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import ConfigParser
import errno
import logging
import os.path
import socket
import sys
from logging.handlers import SysLogHandler

import requests

from elasticarmor import *
from elasticarmor.auth.elasticsearch_backend import ElasticsearchRoleBackend
from elasticarmor.auth.ldap_backend import LdapUserBackend, LdapUsergroupBackend
from elasticarmor.util import format_elasticsearch_error, compare_major_and_minor_version, propertycache
from elasticarmor.util.config import Parser
from elasticarmor.util.daemon import create_daemon_option_parser
from elasticarmor.util.elastic import ElasticConnection
from elasticarmor.util.mixins import LoggingAware

__all__ = ['Settings']


class Settings(LoggingAware, object):
    default_configuration = {
        'log': 'syslog',
        'file': DEFAULT_LOGFILE,
        'facility': 'authpriv',
        'application': APP_NAME.lower(),
        'level': 'error',
        'elasticsearch': DEFAULT_NODE,
        'address': DEFAULT_ADDRESS,
        'port': DEFAULT_PORT,
        'secured': 'false',
        'default_role': None
    }

    default_authentication_config = {
        'msldap': {
            'user_object_class': 'user',
            'user_name_attribute': 'sAMAccountName'
        }
    }

    default_groups_config = {
        'msldap': {
            'user_object_class': 'user',
            'group_object_class': 'group',
            'user_name_attribute': 'sAMAccountName',
            'group_name_attribute': 'sAMAccountName',
            'group_membership_attribute': 'member:1.2.840.113556.1.4.1941:'
        }
    }

    def __init__(self):
        self._group_backend_type = None

    def _exit(self, message, *format_args):
        """Log the given message and exit."""
        self.log.critical(message, *format_args)
        sys.exit(2)

    @property
    def options(self):
        try:
            return Settings.__options
        except AttributeError:
            parser = create_daemon_option_parser(VERSION, prog=APP_NAME.lower())
            parser.add_option('--config', dest='config', metavar='PATH', default=DEFAULT_CONFIG_DIR,
                              help='config PATH [default: %default]')
            parser.add_option('--skip-index-initialization', default=False, action='store_true',
                              help='Whether to skip the initialization of the configuration index.')
            Settings.__options, Settings.__arguments = parser.parse_args()
            return Settings.__options

    @property
    def arguments(self):
        try:
            return Settings.__arguments
        except AttributeError:
            return (self.options, Settings.__arguments)[1]

    @property
    def config(self):
        try:
            return Settings.__config
        except AttributeError:
            parser = Parser(self.default_configuration)
            config_ini = os.path.join(self.options.config, 'config.ini')
            if self._check_file_permissions(config_ini, 'r', suppress_errors=True):
                with open(config_ini) as f:
                    parser.readfp(f)

            Settings.__config = parser
            return Settings.__config

    @property
    def authentication(self):
        try:
            return Settings.__authentication
        except AttributeError:
            parser = Parser()
            authentication_ini = os.path.join(self.options.config, 'authentication.ini')
            if self._check_file_permissions(authentication_ini, 'r', suppress_errors=True):
                with open(authentication_ini) as f:
                    parser.readfp(f)

            Settings.__authentication = parser
            return Settings.__authentication

    @property
    def groups(self):
        try:
            return Settings.__groups
        except AttributeError:
            parser = Parser()
            groups_ini = os.path.join(self.options.config, 'groups.ini')
            if self._check_file_permissions(groups_ini, 'r', suppress_errors=True):
                with open(groups_ini) as f:
                    parser.readfp(f)

            Settings.__groups = parser
            return Settings.__groups

    @property
    def pidfile(self):
        return self.options.pidfile

    @property
    def umask(self):
        return self.options.umask

    @property
    def chdir(self):
        return self.options.chdir

    @property
    def user(self):
        return self.options.user

    @property
    def group(self):
        return self.options.group

    @property
    def detach(self):
        return self.options.detach

    @property
    def log_type(self):
        log_type = self.config.get('logging', 'log').lower()
        types = ['file', 'syslog']
        if log_type in types:
            return log_type

        self._exit('Invalid log type "%s" set. Valid log types are: %s', log_type, ', '.join(types))

    @property
    def log_file(self):
        file_path = self.config.get('logging', 'file')
        self._check_file_permissions(file_path, 'a')
        return file_path

    @property
    def log_application(self):
        return self.config.get('logging', 'application')

    @property
    def log_facility(self):
        facility = self.config.get('logging', 'facility')
        facilities = {
            'user': SysLogHandler.LOG_USER,
            'daemon': SysLogHandler.LOG_DAEMON,
            'authpriv': SysLogHandler.LOG_AUTHPRIV
        }

        try:
            return facilities[facility.lower()]
        except KeyError:
            self._exit('Invalid syslog facility "%s" set. Valid facilities are: %s',
                       facility, ', '.join(facilities.keys()))

    @property
    def log_level(self):
        level = self.config.get('logging', 'level')
        levels = {
            'debug': logging.DEBUG,
            'info': logging.INFO,
            'warning': logging.WARNING,
            'error': logging.ERROR
        }

        try:
            return levels[level.lower()]
        except KeyError:
            self._exit('Invalid logging level "%s" set. Valid log levels are: %s', level, ', '.join(levels.keys()))

    @property
    def log_handler(self):
        if self.log_type == 'syslog':
            handler = SysLogHandler('/dev/log', self.log_facility)
            handler.setFormatter(logging.Formatter(SYSLOG_FORMAT, SYSLOG_DATE_FORMAT))
        else:  # self.log_type == 'file'
            handler = logging.FileHandler(self.log_file, delay=True)
            handler.setFormatter(logging.Formatter(
                    FILE_LOG_FORMAT_DEBUG if self.log_level == logging.DEBUG else FILE_LOG_FORMAT))

        return handler

    @property
    def listen_address(self):
        return self.config.get('proxy', 'address')

    @property
    def listen_port(self):
        return self.config.getint('proxy', 'port')

    @property
    def secure_connection(self):
        return self.config.getboolean('proxy', 'secured')

    @property
    def private_key(self):
        try:
            key_path = os.path.realpath(self.config.get('proxy', 'private_key').strip())
            if not key_path:
                raise ConfigParser.NoOptionError('private_key', 'proxy')
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            return

        self._check_file_permissions(key_path, 'r')
        return key_path

    @property
    def certificate(self):
        try:
            certificate_path = os.path.realpath(self.config.get('proxy', 'certificate').strip())
            if not certificate_path:
                raise ConfigParser.NoOptionError('certificate', 'proxy')
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            return

        self._check_file_permissions(certificate_path, 'r')
        return certificate_path

    @property
    def allow_from(self):
        try:
            return self._create_network_map(self.config.get('proxy', 'allow_from'))
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            return {}

    @property
    def trusted_proxies(self):
        try:
            return self._create_network_map(self.config.get('proxy', 'trusted_proxies'))
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            return {}

    def _create_network_map(self, hosts):
        network_map = {}
        for host_and_port in hosts.split(','):
            try:
                host, port = host_and_port.split(':')
            except ValueError:
                host = host_and_port
                port = None
            else:
                port = int(port) if port.strip() else None

            try:
                ip_list = socket.gethostbyname_ex(host.strip())[2]
            except socket.gaierror as error:
                self.log.warning('Failed to resolve hostname "%s". An error occurred: %s', host, error)
            else:
                for ip in ip_list:
                    if ip not in network_map:
                        if port:
                            network_map[ip] = [port]
                        else:
                            network_map[ip] = None
                    elif network_map[ip] is not None:
                        if port:
                            network_map[ip].append(port)
                        else:
                            network_map[ip] = None

        return network_map

    @property
    @propertycache
    def elasticsearch(self):
        nodes = self.elasticsearch_nodes
        for node in nodes:
            try:
                response = requests.get(node)
                response.raise_for_status()
            except requests.RequestException as error:
                self.log.warning('Node "%s" is not reachable. Error: %s', node, format_elasticsearch_error(error))
            else:
                try:
                    result = response.json()
                    node_version = result['version']['number']
                except (ValueError, TypeError, KeyError):
                    self._exit('There went something wrong with node "%s". Are you'
                               ' sure that this is a Elasticsearch node?', node)

                if not any(compare_major_and_minor_version(node_version, version) == 0
                           for version in SUPPORTED_ELASTICSEARCH_VERSIONS):
                    self.log.warning('Node "%s" has a version which is not officially supported. (%s) You'
                                     ' may experience unexpected or invalid results.', node, node_version)
                    # TODO(3057): Use the following once we've got a test-suite
                    """self.log.warning('Node "%s" has a version which is not officially supported. If you know'
                                     ' that ElasticArmor is fully compatible with version "%s" you can help us'
                                     ' by sending us the results of a test ran against this particular node.',
                                     node, node_version)"""

        return ElasticConnection(nodes)

    @property
    def elasticsearch_nodes(self):
        try:
            nodes = []
            for node in self.config.get('proxy', 'elasticsearch').split(','):
                node = node.lstrip().rstrip(' /')
                if '://' not in node:
                    node = 'http://' + node
                nodes.append(node)

            if not nodes:
                raise ConfigParser.NoOptionError('elasticsearch', 'proxy')
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            self._exit('It is mandatory to provide at least one elasticsearch node.')

        return nodes

    @property
    def role_backend(self):
        return ElasticsearchRoleBackend(self)

    @property
    def auth_backends(self):
        backends = []
        for section_name in self.authentication.sections():
            try:
                backend_type_name = self.authentication.get(section_name, 'backend').lower()
            except ConfigParser.NoOptionError:
                self._exit('Type declaration missing for authentication backend "%s".', section_name)

            if backend_type_name in ('ldap', 'msldap'):
                backend_type = LdapUserBackend
            else:
                self._exit('Unknown type declaration in authentication backend "%s".', section_name)

            defaults = self.default_authentication_config.get(backend_type_name, {})

            def get_option(option_name):
                try:
                    return self.authentication.get(section_name, option_name)
                except ConfigParser.NoOptionError:
                    if option_name in defaults:
                        return defaults[option_name]
                    else:
                        self._exit('Missing "%s" option in authentication backend "%s".', option_name, section_name)

            backend = backend_type(section_name, get_option)
            backend.default_role = self.authentication.get(section_name, 'default_role')
            backends.append(backend)

        return backends

    @property
    def group_backends(self):
        backends = []
        for section_name in self.groups.sections():
            try:
                backend_type_name = self.groups.get(section_name, 'backend').lower()
            except ConfigParser.NoOptionError:
                self._exit('Type declaration missing for group backend "%s".', section_name)

            if backend_type_name in ('ldap', 'msldap'):
                backend_type = LdapUsergroupBackend
            else:
                self._exit('Unknown type declaration in group backend "%s".', section_name)

            defaults = self.default_groups_config.get(backend_type_name, {})

            def get_option(option_name):
                try:
                    return self.groups.get(section_name, option_name)
                except ConfigParser.NoOptionError:
                    if option_name in defaults:
                        return defaults[option_name]
                    else:
                        self._exit('Missing "%s" option in group backend "%s".', option_name, section_name)

            backends.append(backend_type(section_name, get_option))

        return backends

    def _check_file_permissions(self, path, open_mode, suppress_errors=False):
        remove = open_mode[0] == 'w' or (open_mode != 'r' and not os.path.isfile(path))

        try:
            with open(path, open_mode) as f:
                pass
        except (IOError, OSError) as error:
            if not suppress_errors and error.errno != errno.ENXIO:
                if error.errno == errno.EACCES:
                    self._exit('Permission denied to access file "%s" with open mode "%s"', path, open_mode)

                if error.errno == errno.ENOENT:
                    self._exit('No such file or directory: "%s"', path)

                raise
        else:
            if remove:
                os.unlink(path)

            return True
        return False
