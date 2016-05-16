# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

%define revision    1
%define basedir     %{_datadir}/icingaweb2/modules/elasticarmor

Name:       icingaweb2-module-elasticarmor
Version:    0.9
Release:    %{revision}%{?dist}
Summary:    ElasticArmor Configuration Module
Group:      Applications/System
License:    GPLv2+
URL:        https://www.netways.org/projects/elasticarmor
Source0:    https://github.com/NETWAYS/ElasticArmor/archive/v%{version}.tar.gz
Vendor:     NETWAYS GmbH <info@netways.de>
Packager:   NETWAYS GmbH <info@netways.de>

BuildArch:      noarch
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}

Requires:   icingaweb2 >= 2.3.0

%description
This module provides a graphical user-interface to configure ElasticArmor.

%files
%defattr(-,root,root)
%doc AUTHORS COPYING doc
%{basedir}/application
%{basedir}/configuration.php
%{basedir}/doc
%{basedir}/library
%{basedir}/module.info
%{basedir}/public


%prep
%setup -q -n ElasticArmor-%{version}

%build

%install
mkdir -p %{buildroot}/%{basedir}
cp -prv lib/%{name}/* %{buildroot}/%{basedir}
rm %{buildroot}/%{basedir}/doc
cp -prv doc %{buildroot}/%{basedir}

%clean
rm -rf %{buildroot}


%pre

%post


%preun

%postun
