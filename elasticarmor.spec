# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

%{!?__python2: %global __python2 /usr/bin/python2}
%{!?python2_sitelib: %global python2_sitelib %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}

%define revision 1
%define pre_release_tag rc1

Name:       elasticarmor
Version:    1.0
Summary:    HTTP reverse proxy to secure Elasticsearch.
Group:      System Environment/Daemons
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
BuildRequires:  python-setuptools

Requires(post):     /sbin/chkconfig
Requires(preun):    /sbin/chkconfig
Requires(postun):   /sbin/service
Requires(preun):    /sbin/service
Requires:           python < 3
Requires:           python-ldap
Requires:           python-requests

%if 0%{?rhel} == 6
Requires:           python >= 2.6
Requires:           python-simplejson >= 2.1
%else
Requires:           python >= 2.7
%endif

%define configdir %{_sysconfdir}/%{name}

%description
ElasticArmor is a HTTP reverse proxy placed in front of
Elasticsearch to regulate access to its REST api.

%files
%defattr(-,root,root)
%doc AUTHORS COPYING doc
%{python2_sitelib}
%attr(0755,root,root) %{_initddir}/%name


%prep
%setup -q -n ElasticArmor-v%{version}%{?pre_release_tag}

%build

%install
%{__python2} setup.py install --prefix=%{_prefix} --root=%{buildroot}
mkdir -p %{buildroot}%{_initddir}
cp etc/init.d/elasticarmor %{buildroot}%{_initddir}/%{name}

%clean
rm -rf %{buildroot}


%pre

%post
/sbin/chkconfig --add %{name}


%preun
if [ $1 -eq 0 ] ; then
    /sbin/service %{name} stop > /dev/null 2>&1
    /sbin/chkconfig --del %{name}
fi

%postun
if [ $1 -ge 1 ] ; then
    /sbin/service %{name} restart > /dev/null 2>&1 || :
fi
