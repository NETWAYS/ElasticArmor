# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

%define revision    1
%define pre_release_tag rc1
%define basedir     %{_datadir}/icingaweb2/modules/elasticarmor

Name:       icingaweb2-module-elasticarmor
Version:    1.0
Summary:    ElasticArmor Configuration Module
Group:      Applications/System
License:    GPLv2+
URL:        https://www.netways.org/projects/elasticarmor
Source0:    https://github.com/NETWAYS/ElasticArmor/archive/v%{version}%{?pre_release_tag}.tar.gz
Vendor:     NETWAYS GmbH <info@netways.de>
Packager:   NETWAYS GmbH <info@netways.de>

%if %{?pre_release_tag}
Release:    0.%{revision}.%{pre_release_tag}%{?dist}
%else
Release:    %{revision}%{?dist}
%endif

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
%setup -q -n ElasticArmor-v%{version}%{?pre_release_tag}

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
