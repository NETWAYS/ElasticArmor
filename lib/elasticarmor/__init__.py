# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

VERSION = '0.9'
APP_NAME = 'ElasticArmor'
SYSLOG_DATE_FORMAT = '%b %e %H:%M:%S'
SYSLOG_FORMAT ='%(asctime)s %(name)s: %(message)s'
FILE_LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
FILE_LOG_FORMAT_DEBUG = '%(asctime)s - %(process)d:%(threadName)s:%(name)s - %(levelname)s - %(message)s'
SUPPORTED_ELASTICSEARCH_VERSIONS = ['1.7']

CONFIGURATION_INDEX = '.elasticarmor'
CONFIGURATION_TYPE_ROLE = 'role'

DEFAULT_CONFIG_DIR = '/etc/elasticarmor'
DEFAULT_LOGFILE = '/var/log/elasticarmor/elasticarmor.log'
DEFAULT_NODE = 'localhost:9200'
DEFAULT_ADDRESS = 'localhost'
DEFAULT_PORT = 59200
