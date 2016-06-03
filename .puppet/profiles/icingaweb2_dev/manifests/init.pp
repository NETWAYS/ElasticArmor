# Class: icingaweb2_dev
#
#   This class sets up Icinga Web 2.
#
# Parameters:
#
# Actions:
#
# Requires:
#
#   epel
#   icingaweb2
#
# Sample Usage:
#
#   include icingaweb2_dev
#
class icingaweb2_dev {
    include epel

    contain '::mysql::server'
    contain '::mysql::client'
    contain '::mysql::server::account_security'

    contain '::apache'
    contain '::apache::mod::php'

    Exec {
        path => [ '/bin/', '/sbin/' , '/usr/bin/', '/usr/sbin/' ]
    }

    ::mysql::db { 'icingaweb2':
        user      => 'icingaweb2',
        password  => 'icingaweb2',
        host      => 'localhost',
        grant     => ['ALL']
    }

    file { '/root/.my.cnf':
        ensure => present
    }

    class { 'icingaweb2':
        require             => [ Class['epel'], Class['::mysql::server'], File['/root/.my.cnf'] ],
        install_method      => 'package',
        manage_repo         => true,
        initialize          => true,
        manage_apache_vhost => true
    }

    file { '/usr/share/icingaweb2/modules/elasticarmor':
        require => Class['icingaweb2'],
        ensure  => link,
        target  => '/vagrant/lib/icingaweb2-module-elasticarmor'
    }
    -> file { '/etc/icingaweb2/enabledModules/elasticarmor':
        ensure  => link,
        target  => '/usr/share/icingaweb2/modules/elasticarmor'
    }

    # TODO: Use a package or even a puppet module here
    file { '/usr/share/icingaweb2/modules/elasticsearch':
        require => Class['icingaweb2'],
        ensure  => link,
        target  => '/vagrant/lib/icingaweb2-module-elasticsearch'
    }
    -> file { '/etc/icingaweb2/enabledModules/elasticsearch':
        ensure  => link,
        target  => '/usr/share/icingaweb2/modules/elasticsearch'
    }

    # TODO: This is probably also a task for the puppet module
    file { '/etc/icingaweb2/modules/elasticsearch':
        ensure  => directory
    }
    -> file { '/etc/icingaweb2/modules/elasticsearch/config.ini':
        ensure  => file,
        source  => '/vagrant/.puppet/files/icingaweb2-module-elasticsearch/config.ini'
    }

    exec { 'config-role':
        require     => Class['elasticarmor_dev'],
        provider    => shell,
        unless      => 'curl -sf -XHEAD localhost:9200/.elasticarmor/role/config-admin',
        command     => 'curl -XPOST localhost:9200/.elasticarmor/role/config-admin?refresh -d @/vagrant/.puppet/files/icingaweb2-module-elasticarmor/config-admin.json'
    }
    -> exec { 'config-user':
        provider    => shell,
        unless      => 'curl -sf localhost:9200/.elasticarmor/role_user/_search/exists?q=name:admin%20AND%20_parent:config-admin',
        command     => 'curl -XPOST localhost:9200/.elasticarmor/role_user?parent=config-admin -d \'{"name": "admin"}\''
    }

    @user { 'vagrant': ensure => present }
    User <| title == vagrant |> { groups +> 'icingaweb2' }
}