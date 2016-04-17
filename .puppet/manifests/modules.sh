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

