# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

from distutils.version import StrictVersion
from fnmatch import fnmatchcase

__all__ = ['format_ldap_error', 'format_elasticsearch_error', 'compare_major_and_minor_version',
           'pattern_match', 'classproperty', 'propertycache']


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


def _locate_wildcards(pattern):
    """Locate on which side (left and right) the given pattern contains wildcards."""
    left = right = False
    stripped = pattern.rstrip('*?')
    if '*' not in stripped and '?' not in stripped:
        right = True
    else:
        if stripped != pattern:
            right = True

        left = stripped.lstrip('*?') != stripped

    return left, right


def pattern_match(wild, tame):
    """Return whether the given strings match.
    Tries to produce a match even if both strings contain wildcards.
    """

    if wild == '*' or tame == wild:
        return True  # Bail out early if it's clear that a match is possible

    if '*' not in tame and '?' not in tame:
        if '*' not in wild and '?' not in wild:
            return False  # Neither of the strings contains wildcards so there is no chance they will ever match

        return fnmatchcase(tame, wild)  # It's a usual literal == pattern comparison
    elif '*' not in wild and '?' not in wild:
        return False  # The tame string is wild but the wild one isn't thus a match is impossible

    tame_left, tame_right = _locate_wildcards(tame)
    wild_left, wild_right = _locate_wildcards(wild)
    if tame_left and not wild_left or tame_right and not wild_right:
        return False  # The tame string contains wildcards where the wild one doesn't thus a match is impossible

    # Now the chances are good that we're able to produce a match but we must strip all asterisk wildcards from
    # the tame string as they may cause false positives if question mark wildcards are present in the wild one
    return fnmatchcase(tame.replace('*', ''), wild)


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
