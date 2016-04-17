# -*- mode: ruby -*-
# vi: set ft=ruby :

# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

VAGRANTFILE_API_VERSION = "2"
VAGRANT_REQUIRED_VERSION = "1.5.0"

if ! defined? Vagrant.require_version
  if Gem::Version.new(Vagrant::VERSION) < Gem::Version.new(VAGRANT_REQUIRED_VERSION)
    puts "Vagrant >= " + VAGRANT_REQUIRED_VERSION + " required. Your version is " + Vagrant::VERSION
    exit 1
  end
else
  Vagrant.require_version ">= " + VAGRANT_REQUIRED_VERSION
end

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "bento/centos-7.2"

  config.vm.network "forwarded_port", guest: 5601, host: 8080, auto_correct: true
  config.vm.network "forwarded_port", guest: 9200, host: 9200, auto_correct: true

  config.vm.synced_folder ".", "/vagrant"

  config.vm.provider :vmware_workstation do |v|
    v.vmx["memsize"] = "1024"
    v.vmx["numvcpus"] = "1"
  end

  config.vm.provider :parallels do |p|
    p.name = "ElasticArmor Development"

    # Update Parallels Tools automatically
    p.update_guest_tools = true

    # Set power consumption mode to "Better Performance"
    p.optimize_power_consumption = false

    p.memory = 1024
    p.cpus = 2
  end

  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = "1024"
  end

  config.vm.provision :shell, :path => ".puppet/manifests/puppet.sh"
  config.vm.provision :shell, :path => ".puppet/manifests/modules.sh"

  config.vm.provision "puppet" do |puppet|
    puppet.module_path = [ ".puppet/modules", ".puppet/profiles" ]
    puppet.manifests_path = ".puppet/manifests"
    puppet.manifest_file = "site.pp"
    puppet.options = "--parser=future"
  end
end
