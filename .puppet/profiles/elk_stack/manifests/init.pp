# Class: elk_stack
#
#   This class installs Elasticsearch, Logstash and Kibana.
#
# Parameters:
#
# Actions:
#
# Requires:
#
#   - java
#   - elasticsearch
#   - logstash
#   - kibana
#
# Sample Usage:
#
#   include elk_stack
#
class elk_stack {
    class { 'elasticsearch':
        package_url  => 'https://download.elastic.co/elasticsearch/elasticsearch/elasticsearch-1.7.5.noarch.rpm',
        java_install => true
    }

    elasticsearch::instance { 'es-01': }

    class { 'logstash':
        require     => Class['elasticsearch'],
        package_url => 'https://download.elastic.co/logstash/logstash/packages/centos/logstash-2.3.1-1.noarch.rpm'
    }

    logstash::configfile { 'configname':
        content => template('/vagrant/.puppet/files/logstash/logstash.conf')
    }

    class { 'kibana':
        version => '4.1.6',
        es_url  => 'http://localhost:59200'
    }
}
