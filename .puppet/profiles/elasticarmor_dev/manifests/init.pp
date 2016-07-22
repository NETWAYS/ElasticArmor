# Class: elasticarmor_dev
#
#   This class sets up a development environment for ElasticArmor.
#
# Parameters:
#
# Actions:
#
# Requires:
#
# Sample Usage:
#
#   include elasticarmor_dev
#
class elasticarmor_dev {
    file { '/etc/elasticarmor':
        ensure => directory
    }
    -> file { '/etc/elasticarmor/config.ini':
        notify => Service['elasticarmor'],
        ensure => file,
        source => '/vagrant/.puppet/files/elasticarmor/config.ini'
    }

    exec { 'config-index':
        require     => Class['elasticsearch'],
        provider    => shell,
        unless      => 'sleep 10 && curl -sf -XHEAD localhost:9200/.elasticarmor',
        command     => 'curl -XPOST localhost:9200/.elasticarmor -d @/vagrant/.puppet/files/elasticarmor/config-index.json'
    }
    -> exec { 'server-role':
        provider    => shell,
        unless      => 'curl -sf -XHEAD localhost:9200/.elasticarmor/role/kibana-server',
        command     => 'curl -XPOST localhost:9200/.elasticarmor/role/kibana-server?refresh -d @/vagrant/.puppet/files/elasticarmor/kibana-server.json'
    }
    -> exec { 'server-user':
        provider    => shell,
        unless      => 'curl -sf localhost:9200/.elasticarmor/role_user/_search/exists?q=name:localhost%20AND%20_parent:kibana-server',
        command     => 'curl -XPOST localhost:9200/.elasticarmor/role_user?parent=kibana-server -d \'{"name": "localhost"}\''
    }
    -> exec { 'client-role':
        provider    => shell,
        unless      => 'curl -sf -XHEAD localhost:9200/.elasticarmor/role/kibana-user',
        command     => 'curl -XPOST localhost:9200/.elasticarmor/role/kibana-user?refresh -d @/vagrant/.puppet/files/elasticarmor/kibana-user.json'
    }
    -> exec { 'client-user':
        provider    => shell,
        unless      => 'curl -sf localhost:9200/.elasticarmor/role_user/_search/exists?q=name:kibana%20AND%20_parent:kibana-user',
        command     => 'curl -XPOST localhost:9200/.elasticarmor/role_user?parent=kibana-user -d \'{"name": "kibana"}\''
    }

    package { 'python-ldap': }
    package { 'python-requests': }

    file { '/usr/lib/python2.7/site-packages/elasticarmor':
        ensure => link,
        target => '/vagrant/lib/elasticarmor'
    }
    -> file { '/etc/init.d/elasticarmor':
        ensure => file,
        source => '/vagrant/etc/init.d/elasticarmor'
    }
    -> group { 'elasticarmor':
        ensure  => present,
        system  => true
    }
    -> user { 'elasticarmor':
        ensure  => present,
        system  => true,
        shell   => '/sbin/nologin',
        comment => 'elasticarmor',
        gid     => 'elasticarmor'
    }
    -> file { '/var/log/elasticarmor':
        ensure => directory,
        owner  => 'elasticarmor',
        group  => 'elasticarmor'
    }
    -> service { 'elasticarmor':
        require => [ Class['elasticsearch'], Package['python-ldap'], Package['python-requests'] ],
        ensure  => running,
        enable  => true
    }
}
