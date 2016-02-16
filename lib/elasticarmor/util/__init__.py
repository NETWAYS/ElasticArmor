# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

from distutils.version import StrictVersion

__all__ = ['format_ldap_error', 'format_elasticsearch_error', 'compare_major_and_minor_version',
           'classproperty', 'propertycache']


def format_ldap_error(error):
    """Return a string representation of the given LDAPError."""
    if 'desc' in error.args[0] and 'info' in error.args[0]:
        error_message = '{0} ({1})'.format(error.args[0]['desc'], error.args[0]['info'])
    elif 'desc' in error.args[0]:
        error_message = error.args[0]['desc']
    elif 'info' in error.args[0]:
        error_message = error.args[0]['info']
    else:
        error_message = str(error)

    return error_message


def format_elasticsearch_error(error):
    """Return a string representation of the given RequestException."""
    try:
        return error.response.json()['error']
    except AttributeError:
        return str(error)
    except (ValueError, KeyError):
        return error.response.content


def compare_major_and_minor_version(version_to_compare, version_to_compare_with):
    """Compare both versions and return 0 if they're equal, 1 if version_to_compare
    is newer than version_to_compare_with and -1 otherwise.

    This will only compare the major and minor part of a version. Patch level and
    build number will be ignored, if present.
    """

    list_to_compare = version_to_compare.split('.')
    list_to_compare_with = version_to_compare_with.split('.')
    return cmp(StrictVersion('.'.join(list_to_compare[:2])), StrictVersion('.'.join(list_to_compare_with[:2])))


class classproperty(object):
    """Dead-simple @classproperty decorator

    Usage:
        class Foo(object):
            @classproperty
            def bar(cls):
                return cls

        assert Foo.bar is Foo
        assert Foo().bar is Foo

    Original solution by Denis Ryzhkov @ http://stackoverflow.com/a/13624858."""

    def __init__(self, func):
        self.func = func

    def __get__(self, instance, owner):
        return self.func(owner)


class propertycache(object):
    """Cache decorator for object properties.

    Usage:
        class Foo(object):
            @property
            @propertycache
            def bar(self):
                return <some-value>
    """

    def __init__(self, func):
        self.func = func
        self.result = None

    def __call__(self, instance):
        if self.result is None:
            self.result = self.func(instance)

        return self.result
