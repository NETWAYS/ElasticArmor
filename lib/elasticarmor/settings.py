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
from elasticarmor.util import format_elasticsearch_error, compare_major_and_minor_version, propertycache
from elasticarmor.util.auth import LdapUsergroupBackend, ElasticsearchRoleBackend
from elasticarmor.util.config import Parser
from elasticarmor.util.daemon import get_daemon_option_parser
from elasticarmor.util.elastic import ElasticConnection
from elasticarmor.util.mixins import LoggingAware

__all__ = ['Settings']


class Settings(LoggingAware, object):
    default_configuration = {
        'log': 'syslog',
        'file': DEFAULT_LOGFILE,
        'facility': 'authpriv',
        'application': APP_NAME,
        'level': 'error',
        'elasticsearch': DEFAULT_NODE,
        'allow_from': 'localhost',
        'address': DEFAULT_ADDRESS,
        'port': DEFAULT_PORT,
        'secured': 'false',
        'backend': 'none'
    }

    def __init__(self):
        self._group_backend_type = None

    def _exit(self, message, *format_args):
        """Log the given message and exit."""
        self.log.critical(message, *format_args)
        sys.exit(2)

    def _get_or_exit(self, section, option, message, *format_args):
        """Return the given option in the given section or log the given message and exit."""
        try:
            return self.config.get(section, option)
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            self._exit(message, *format_args)

    @property
    def options(self):
        try:
            return Settings.__options
        except AttributeError:
            parser = get_daemon_option_parser(VERSION, prog=APP_NAME)
            parser.add_option('--config', dest='config', metavar='FILE', default=DEFAULT_CONFIG,
                              help='config FILE [default: %default]')
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
            self._check_file_permissions(self.options.config, 'r')
            parser = Parser(self.default_configuration)
            with open(self.options.config) as f:
                parser.readfp(f)
            Settings.__config = parser
            return Settings.__config

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
        return self.config.get('logging', 'file')

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
        allow_from = {}
        for host_and_port in self.config.get('proxy', 'allow_from').split(','):
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
                    if ip not in allow_from:
                        if port:
                            allow_from[ip] = [port]
                        else:
                            allow_from[ip] = None
                    elif allow_from[ip] is not None:
                        if port:
                            allow_from[ip].append(port)
                        else:
                            allow_from[ip] = None

        return allow_from

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
    def group_backend(self):
        self._group_backend_type = self.config.get('group_backend', 'backend').lower()
        if self._group_backend_type in ('ldap', 'msldap'):
            return LdapUsergroupBackend(self)

    @property
    def role_backend(self):
        return ElasticsearchRoleBackend(self)

    @property
    def ldap_url(self):
        return self._get_or_exit('ldap', 'url',
                                 'It is mandatory to provide a proper URL pointing to the LDAP server to use.')

    @property
    def ldap_bind_dn(self):
        return self._get_or_exit('ldap', 'bind_dn',
                                 'It is mandatory to provide a DN with which to bind to the LDAP server.')

    @property
    def ldap_bind_pw(self):
        return self._get_or_exit('ldap', 'bind_pw',
                                 'It is mandatory to provide a password with which to bind to the LDAP server.')

    @property
    def ldap_root_dn(self):
        return self._get_or_exit('ldap', 'root_dn',
                                 'It is mandatory to provide the root DN of the LDAP server.')

    @property
    def ldap_user_base_dn(self):
        return self._get_or_exit('ldap', 'user_base_dn',
                                 'It is mandatory to provide a DN where to locate users.')

    @property
    def ldap_group_base_dn(self):
        return self._get_or_exit('ldap', 'group_base_dn',
                                 'It is mandatory to provide a DN where to locate groups.')

    @property
    def ldap_user_object_class(self):
        try:
            return self.config.get('ldap', 'user_object_class')
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            if self._group_backend_type == 'msldap':
                return 'user'

            self._exit('It is mandatory to provide a LDAP user\'s object class.')

    @property
    def ldap_group_object_class(self):
        try:
            return self.config.get('ldap', 'group_object_class')
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            if self._group_backend_type == 'msldap':
                return 'group'

            self._exit('It is mandatory to provide a LDAP group\'s object class.')

    @property
    def ldap_user_name_attribute(self):
        try:
            return self.config.get('ldap', 'user_name_attribute')
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            if self._group_backend_type == 'msldap':
                return 'sAMAccountName'

            self._exit('It is mandatory to provide an attribute where a user\'s name is stored.')

    @property
    def ldap_group_name_attribute(self):
        try:
            return self.config.get('ldap', 'group_name_attribute')
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            if self._group_backend_type == 'msldap':
                return 'sAMAccountName'

            self._exit('It is mandatory to provide an attribute where a group\'s name is stored.')

    @property
    def ldap_group_membership_attribute(self):
        try:
            return self.config.get('ldap', 'group_membership_attribute')
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            if self._group_backend_type == 'msldap':
                return 'member:1.2.840.113556.1.4.1941:'

            self._exit('It is mandatory to provide an attribute where a group\'s members are stored.')

    def _check_file_permissions(self, path, open_mode):
        remove = open_mode[0] == 'w' or (open_mode != 'r' and not os.path.isfile(path))

        try:
            with open(path, open_mode) as f:
                pass
        except (IOError, OSError) as error:
            if error.errno != errno.ENXIO:
                if error.errno == errno.EACCES:
                    self._exit('Permission denied to access file "%s" with open mode "%s"', path, open_mode)

                if error.errno == errno.ENOENT:
                    self._exit('No such file or directory: "%s"', path)

                raise
        else:
            if remove:
                os.unlink(path)
