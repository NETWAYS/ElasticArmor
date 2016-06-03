# <a id="installation"></a> Installation

## <a id="installation-requirements"></a> Requirements

* [Python 2.6 or 2.7](https://www.python.org/)
* [python-setuptools](https://pythonhosted.org/setuptools/)
* [python-requests](http://docs.python-requests.org/en/master/) (>= 2.4.2)
* [python-ldap](https://www.python-ldap.org/)

**Python 2.6:**
* [python-simplejson](https://simplejson.readthedocs.org/en/latest/) (>= 2.1)

## <a id="installation-from-source"></a> From Source

First of all, download and extract the [tar-ball](https://github.com/NETWAYS/elasticarmor/archive/master.tar.gz):
```shell
wget -O elasticarmor.tar.gz https://github.com/NETWAYS/elasticarmor/archive/master.tar.gz
tar -xzvf elasticarmor.tar.gz && cd elasticarmor-master
```

Install ElasticArmor as Python module:
```shell
python2 setup.py install
```

Install the init script:

**Debian**
```shell
install -m 0744 etc/init.d/elasticarmor /etc/init.d/elasticarmor
update-rc.d elasticarmor defaults
```

**Others**
```shell
install -m 0744 etc/init.d/elasticarmor /etc/init.d/elasticarmor
chkconfig --add elasticarmor
```

Create the system user and group:

```shell
useradd -c "elasticarmor" -s /sbin/nologin -r elasticarmor
```

Done. You can now start [configuring ElasticArmor](01-About.md#about-configuration).
