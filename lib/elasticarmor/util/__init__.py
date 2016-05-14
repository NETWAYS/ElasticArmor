# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import re
from distutils.version import StrictVersion

__all__ = ['format_ldap_error', 'format_elasticsearch_error', 'compare_major_and_minor_version',
           'pattern_match', 'pattern_compare', 'classproperty', 'propertycache', 'strip_quotes']

CACHE_MAX_SIZE = 1000
_pattern_cache = {}


def format_ldap_error(error):
    """Return a string representation of the given LDAPError."""
    if len(error.args) == 2:
        if error.args[0] == 0:
            error_message = 'Connection failed'
        else:
            error_message = 'Unknown error: {0}'.format(error.args[0])
    elif 'desc' in error.args[0] and 'info' in error.args[0]:
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


def _apply_pattern(pattern, subject):
    """Return whether the given subject matches the given pattern."""
    if pattern not in _pattern_cache:
        if len(_pattern_cache) >= CACHE_MAX_SIZE:
            _pattern_cache.clear()

        _pattern_cache[pattern] = re.compile(re.escape(pattern).replace('\\*', '.*'))
    return _pattern_cache[pattern].match(subject) is not None


def _locate_wildcards(pattern):
    """Locate where (left, center and right) the given pattern contains wildcards."""
    left = center = right = False
    right_stripped = pattern.rstrip('*')
    if '*' not in right_stripped:
        right = True
    else:
        if right_stripped != pattern:
            right = True

        left_stripped = right_stripped.lstrip('*')
        if '*' not in left_stripped:
            left = True
        else:
            center = True
            if left_stripped != right_stripped:
                left = True

    return left, center, right


def pattern_match(wild, tame):
    """Return whether the given strings match. Tries hard to produce a match even if both strings contain wildcards."""
    if wild == '*' or tame == wild:
        return True  # Bail out early if it's clear that a match is inevitable

    if '*' not in tame:
        if '*' not in wild:
            return False  # Neither of the strings contains wildcards so there is no chance they will ever match

        return _apply_pattern(wild, tame)  # It's a usual literal == pattern comparison
    elif '*' not in wild:
        return False  # The tame string is wild but the wild one isn't thus a match is impossible

    tame_left, tame_center, tame_right = _locate_wildcards(tame)
    wild_left, wild_center, wild_right = _locate_wildcards(wild)
    if tame_left and not wild_left or tame_center and not wild_center or tame_right and not wild_right:
        return False  # The tame string contains wildcards where the wild one doesn't thus a match is impossible
    elif not tame_center:
        # In case the tame string does not contain any wildcards in its center we can still perform a simple match
        # as any wildcard in the tame string has an equal counterpart in the wild one, so it's safe to ignore them
        return _apply_pattern(wild, tame)

    # We'll need the wild string without any wildcards on its left
    # or right a few times now, so pre-process it to save some time
    stripped_wild = wild.strip('*')

    # Now it gets difficult. Both strings have wildcards in its center. This
    # is difficult because of the nature how wildcards behave: They're greedy
    if stripped_wild.count('*') == 1:
        # But this is also an opportunity for us, as if the wild string does
        # only contain a single wildcard this makes our task a LOT easier
        left, _, right = stripped_wild.partition('*')
        if wild_left:
            left = re.compile('.*' + left)  # Note that the leading ^ is omitted here because of using re.match
        elif not tame.startswith(left):
            return False

        if wild_right:
            right = re.compile(right + '.*$')
        elif not tame.endswith(right):
            return False

        return (not wild_left or left.match(tame) is not None) and (not wild_right or right.search(tame) is not None)

    # But if there are multiple wildcards in the center of wild.. I'll now leave this as a task for the
    # reader, or myself. But this is really an edge-case which I don't think anyone is needing at all
    return False  # TODO: Raise an exception instead


def pattern_compare(pattern, other, default=None):
    """Return whether the given pattern is greater than, less than or equal to the given other pattern.
    Raises ValueError in case the given patterns are incompatible to each other and no default is given.

    """
    if pattern_match(pattern, other):
        return 0 if pattern == other else 1
    elif pattern_match(other, pattern):
        return -1
    elif default is None:
        # TODO: Raise a more specific exception instead of ValueError
        raise ValueError('Incompatible patterns given ({0}, {1})'.format(pattern, other))
    else:
        return default


class classproperty(object):
    """Dead-simple @classproperty decorator

    Usage:
        class Foo(object):
            @classproperty
            def bar(cls):
                return cls

        assert Foo.bar is Foo
        assert Foo().bar is Foo

    Original solution by Denis Ryzhkov @ http://stackoverflow.com/a/13624858.
    """

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


def strip_quotes(buf):
    """Remove leading and trailing quotes from the given string and return only the enclosed content."""
    try:
        if buf.startswith("'") or buf.startswith('"'):
            buf = buf[1:]
        if buf.endswith("'") or buf.endswith('"'):
            buf = buf[:-1]
    except AttributeError:
        raise TypeError('Expected type string, got %s instead' % type(buf))

    return buf
