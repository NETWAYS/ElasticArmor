#!/bin/bash

if [ ! -d /vagrant/.puppet/modules/java ]; then
    echo "Installing java module..."
    puppet module install puppetlabs-java --modulepath /vagrant/.puppet/modules
fi

if [ ! -d /vagrant/.puppet/modules/elasticsearch ]; then
    echo "Installing elasticsearch module..."
    puppet module install elasticsearch-elasticsearch --modulepath /vagrant/.puppet/modules
fi

if [ ! -d /vagrant/.puppet/modules/logstash ]; then
    echo "Installing logstash module..."
    puppet module install elasticsearch-logstash --modulepath /vagrant/.puppet/modules
fi

if [ ! -d /vagrant/.puppet/modules/kibana ]; then
    echo "Installing kibana module..."
    puppet module install jlambert121-kibana --modulepath /vagrant/.puppet/modules
fi

if [ ! -d /vagrant/.puppet/modules/epel ]; then
    echo "Installing epel module..."
    puppet module install stahnma-epel --modulepath /vagrant/.puppet/modules
fi

if [ ! -d /vagrant/.puppet/modules/mysql ]; then
    echo "Installing mysql module..."
    puppet module install puppetlabs-mysql --modulepath /vagrant/.puppet/modules
fi

if [ ! -d /vagrant/.puppet/modules/icingaweb2 ]; then
    echo "Installing icingaweb2 module..."
    wget --quiet -O /tmp/icinga-icingaweb2.tar.gz https://github.com/Icinga/puppet-icingaweb2/archive/master.tar.gz
    puppet module install /tmp/icinga-icingaweb2.tar.gz --modulepath /vagrant/.puppet/modules
fi

