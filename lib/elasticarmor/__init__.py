# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

VERSION = '1.0rc2'
APP_NAME = 'ElasticArmor'
SYSLOG_DATE_FORMAT = '%b %e %H:%M:%S'
SYSLOG_FORMAT ='%(asctime)s %(name)s: %(message)s'
FILE_LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
FILE_LOG_FORMAT_DEBUG = '%(asctime)s - %(process)d:%(threadName)s:%(name)s - %(levelname)s - %(message)s'
SUPPORTED_ELASTICSEARCH_VERSIONS = ['1.7']

CONFIGURATION_INDEX = '.elasticarmor'
CONFIGURATION_TYPE_ROLE = 'role'
CONFIGURATION_TYPE_USER = 'user'
CONFIGURATION_TYPE_ROLE_USER = 'role_user'
CONFIGURATION_TYPE_ROLE_GROUP = 'role_group'
CONFIGURATION_INDEX_SETTINGS = {
    "settings": {
        "analysis": {
            "analyzer": {
                "lowercase_keyword": {
                    "type": "custom",
                    "filter": "lowercase",
                    "tokenizer": "keyword"
                }
            }
        }
    },
    "mappings": {
        CONFIGURATION_TYPE_USER: {
            "properties": {
                "password_hash": {
                    "type": "binary"
                }
            }
        },
        CONFIGURATION_TYPE_ROLE: {
            "properties": {
                "privileges": {
                    "type": "object",
                    "enabled": False
                }
            }
        },
        CONFIGURATION_TYPE_ROLE_USER: {
            "_parent": {
                "type": CONFIGURATION_TYPE_ROLE
            },
            "properties": {
                "name": {
                    "type": "string",
                    "analyzer": "lowercase_keyword"
                },
                "backend": {
                    "type": "string",
                    "analyzer": "lowercase_keyword"
                }
            }
        },
        CONFIGURATION_TYPE_ROLE_GROUP: {
            "_parent": {
                "type": CONFIGURATION_TYPE_ROLE
            },
            "properties": {
                "name": {
                    "type": "string",
                    "analyzer": "lowercase_keyword"
                },
                "backend": {
                    "type": "string",
                    "analyzer": "lowercase_keyword"
                }
            }
        }
    }
}

DEFAULT_CONFIG_DIR = '/etc/elasticarmor'
DEFAULT_LOGFILE = '/var/log/elasticarmor/elasticarmor.log'
DEFAULT_NODE = 'localhost:9200'
DEFAULT_ADDRESS = 'localhost'
DEFAULT_PORT = 59200
