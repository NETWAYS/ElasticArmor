# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

from elasticarmor.auth import AuthorizationError
from elasticarmor.util import pattern_compare
from elasticarmor.util.elastic import ElasticRole

__all__ = ['RoleError', 'Role', 'RestrictionError', 'Restriction', 'IndexPattern', 'TypePattern', 'FieldPattern']


class RoleError(AuthorizationError):
    """Raised by class Role in case of an error."""
    pass


class Role(ElasticRole):
    @property
    def _privileges(self):
        try:
            return self.__privileges
        except AttributeError:
            if 'fields' in self.privileges and 'types' not in self.privileges:
                raise RoleError('Role "{0}" defines field restrictions but not any type restrictions'.format(self.id))
            elif 'types' in self.privileges and 'indices' not in self.privileges:
                raise RoleError('Role "{0}" defines type restrictions but not any index restrictions'.format(self.id))

            privileges = {}
            if 'cluster' in self.privileges:
                privileges['cluster'] = self.privileges['cluster']
            if 'indices' in self.privileges:
                privileges['indices'] = dict(
                    (Restriction([k]), v)
                    for k, v in self.privileges['indices'].iteritems())
            if 'types' in self.privileges:
                privileges['types'] = dict(
                    (Restriction([p.index, k]), v)
                    for k, v in self.privileges['types'].iteritems()
                    for p in (p for r in privileges['indices'] for p in r.includes))
            if 'fields' in self.privileges:
                privileges['fields'] = dict(
                    (Restriction([p.index, p.type, k]), v)
                    for k, v in self.privileges['fields'].iteritems()
                    for p in (p for r in privileges['types'] for p in r.includes))

            if not privileges:
                raise RoleError('Role "{0}" does not define any privileges'.format(self.id))

            self.__privileges = privileges
            return self.__privileges

    def get_restrictions(self, permission, index=None, document_type=None):
        """Return all restrictions for the given context which grant the given permission.
        Climbs up the entire privilege hierarchy in case a restriction inherits permissions
        until a partially matching parent is found that grants the permission.

        """
        restrictions, candidates = [], []
        if document_type is not None:
            pattern = TypePattern(index, document_type)
            for restriction, permissions in self._privileges.get('fields', {}).iteritems():
                if restriction.matches(pattern):
                    if not permissions:
                        # Restrictions without any permissions are considered inheriting
                        candidates.append(restriction)
                    elif any(self._match_permissions(permission, p) for p in permissions):
                        # Whereas restrictions with at least one permission are required
                        # to match and if not, are ignored
                        restrictions.append(restriction)

        if index is not None and (not restrictions or candidates):
            if candidates:
                # If there are already candidates, ensure that these are not touched and
                # use a pattern that represents the full context to avoid false-positives
                register_candidates = False
                pattern = TypePattern(index, document_type)
            else:
                register_candidates = True
                pattern = IndexPattern(index)

            for restriction, permissions in self._privileges.get('types', {}).iteritems():
                if restriction.matches(pattern):
                    if not permissions:
                        if register_candidates:
                            candidates.append(restriction)
                    elif any(self._match_permissions(permission, p) for p in permissions):
                        if register_candidates:
                            # Avoid touching the restrictions as well, since we're
                            # interested in the remaining candidates only
                            restrictions.append(restriction)
                        elif candidates:
                            # Any matching parent allows to include the remaining
                            # candidates in the final result, at once
                            restrictions.extend(candidates)
                            return restrictions

        if not restrictions or candidates:
            if candidates:
                register_candidates = False
                pattern = IndexPattern(index)
            else:
                register_candidates = True
                pattern = None

            for restriction, permissions in self._privileges.get('indices', {}).iteritems():
                if pattern is None or restriction.matches(pattern):
                    if not permissions:
                        if register_candidates:
                            candidates.append(restriction)
                    elif any(self._match_permissions(permission, p) for p in permissions):
                        if register_candidates:
                            restrictions.append(restriction)
                        elif candidates:
                            restrictions.extend(candidates)
                            return restrictions

        if candidates and any(self._match_permissions(permission, p) for p in self._privileges.get('cluster', [])):
            restrictions.extend(candidates)

        return restrictions

    def permits(self, permission, index=None, document_type=None, field=None):
        """Return whether this role permits the given permission in the given context.
        May return True if the permission has been granted at a higher level.

        """
        if field is not None:
            field_match = self._grants_permission(
                permission, self._privileges.get('fields', {}), FieldPattern(index, document_type, field))
            if field_match is not None:
                return field_match

        if document_type is not None:
            type_match = self._grants_permission(
                permission, self._privileges.get('types', {}), TypePattern(index, document_type))
            if type_match is not None:
                return type_match

        if index is not None:
            index_match = self._grants_permission(
                permission, self._privileges.get('indices', {}), IndexPattern(index))
            if index_match is not None:
                return index_match

        return any(self._match_permissions(permission, p) for p in self._privileges.get('cluster', []))

    def _grants_permission(self, permission, privileges, pattern=None):
        """Helper for method permit()."""
        if not privileges:
            return

        check_parents = False
        for restriction, permissions in privileges.iteritems():
            if pattern is None or restriction.matches(pattern):
                if not permissions:
                    check_parents = True
                elif any(self._match_permissions(permission, p) for p in permissions):
                    return True

        return None if check_parents else False

    @staticmethod
    def _match_permissions(required, granted):
        """Return whether the given granted permission matches the given required permission."""
        if not required.endswith('/*'):
            if granted.endswith('/*'):
                granted = granted[:-2]

            return required.startswith(granted)
        elif not granted.endswith('/*'):
            return granted.startswith(required[:-2])
        else:
            return required.startswith(granted[:-2]) or granted.startswith(required[:-2])


class RestrictionError(AuthorizationError):
    """Raised by class Restriction in case of an error."""
    pass


class Restriction(object):
    """Restriction object which represents a configured client restriction."""

    def __init__(self, restriction):
        self._parsed = False
        self._includes = []
        self._excludes = []

        self.raw_restriction = restriction

    def __str__(self):
        return '/'.join(self.raw_restriction)

    def __hash__(self):
        return hash(tuple(self.raw_restriction))

    def __repr__(self):
        return "Restriction({0!r})".format(self.raw_restriction)

    def __eq__(self, other):
        try:
            return self.raw_restriction == other.raw_restriction
        except AttributeError:
            return NotImplemented

    @property
    def includes(self):
        self._parse_restriction()
        return self._includes[:]

    @property
    def excludes(self):
        self._parse_restriction()
        return self._excludes[:]

    def _parse_restriction(self):
        if self._parsed:
            return

        type_restriction = field_restriction = False
        if len(self.raw_restriction) == 1:
            type_factory = IndexPattern
            type_pattern = self.raw_restriction[0]
        elif len(self.raw_restriction) == 2:
            type_restriction = True
            type_pattern = self.raw_restriction[1]
            type_factory = lambda p: TypePattern(self.raw_restriction[0], p)
        else:
            field_restriction = True
            type_pattern = self.raw_restriction[2]
            type_factory = lambda p: FieldPattern(self.raw_restriction[0], self.raw_restriction[1], p)

        for pattern in (s.strip() for s in type_pattern.split(',')):
            if pattern.startswith('-'):
                self._excludes.append(type_factory(pattern[1:]))
            elif pattern:
                if type_restriction and '*' in pattern:
                    raise RestrictionError('Type restrictions with wildcards are not supported'
                                           ' ("{0}")'.format(pattern))
                elif field_restriction and len(pattern) > 1 and pattern.startswith('*'):
                    raise RestrictionError('Field restrictions with leading wildcards are not supported'
                                           ' ("{0}")'.format(pattern))

                self._includes.append(type_factory(pattern))

        if not self._includes:
            raise RestrictionError('Restriction "{0}" does not provide any includes'.format(self))

        self._parsed = True

    def matches(self, pattern):
        """Return whether the given pattern matches this restriction."""
        self._parse_restriction()
        return any(pattern <= include for include in self._includes) and \
            not any(exclude >= pattern for exclude in self._excludes)


class IndexPattern(object):
    """IndexPattern container which provides methods to perform rich comparisons with other patterns.

    A pattern is either a simple string, an instance of IndexPattern, TypePattern or FieldPattern.
    If it's an instance of TypePattern or FieldPattern only their index part will be compared.
    """

    def __init__(self, index_pattern):
        self.index = index_pattern

    def __str__(self):
        return self.index

    def __hash__(self):
        return hash(self.index)

    def __repr__(self):
        return "IndexPattern('{0}')".format(self.index)

    def __lt__(self, other):
        try:
            other_index = other if isinstance(other, basestring) else other.index
        except AttributeError:
            return False
        else:
            return pattern_compare(self.index, other_index, 1) == -1

    def __le__(self, other):
        try:
            other_index = other if isinstance(other, basestring) else other.index
        except AttributeError:
            return False
        else:
            return pattern_compare(self.index, other_index, 1) != 1

    def __eq__(self, other):
        try:
            other_index = other if isinstance(other, basestring) else other.index
        except AttributeError:
            return False
        else:
            return pattern_compare(self.index, other_index, 1) == 0

    def __ne__(self, other):
        try:
            other_index = other if isinstance(other, basestring) else other.index
        except AttributeError:
            return True
        else:
            return pattern_compare(self.index, other_index, 1) != 0

    def __gt__(self, other):
        try:
            other_index = other if isinstance(other, basestring) else other.index
        except AttributeError:
            return False
        else:
            return pattern_compare(self.index, other_index, -1) == 1

    def __ge__(self, other):
        try:
            other_index = other if isinstance(other, basestring) else other.index
        except AttributeError:
            return False
        else:
            return pattern_compare(self.index, other_index, -1) != -1


class TypePattern(object):
    """TypePattern container which provides methods to perform rich comparisons with other patterns.

    A pattern is either a simple string an instance of TypePattern or FieldPattern. If
    it's an instance of FieldPattern only their index and type parts will be compared.
    It's not possible to compare an instance of TypePattern with an instance of IndexPattern.
    """

    def __init__(self, index_pattern, type_pattern):
        self.index = index_pattern
        self.type = type_pattern

    def __str__(self):
        return self.type

    def __hash__(self):
        return hash((self.index, self.type))

    def __repr__(self):
        return "TypePattern('{0}', '{1}')".format(self.index, self.type)

    def __lt__(self, other):
        try:
            other_type = other.type
            other_index = other.index
        except AttributeError:
            if isinstance(other, basestring):
                other_type = other
            else:
                return False
        else:
            try:
                pattern_compare(self.index, other_index)
            except ValueError:
                return False

        return pattern_compare(self.type, other_type, 1) == -1

    def __le__(self, other):
        try:
            other_type = other.type
            other_index = other.index
        except AttributeError:
            if isinstance(other, basestring):
                other_type = other
            else:
                return False
        else:
            try:
                pattern_compare(self.index, other_index)
            except ValueError:
                return False

        return pattern_compare(self.type, other_type, 1) != 1

    def __eq__(self, other):
        try:
            other_type = other.type
            other_index = other.index
        except AttributeError:
            if isinstance(other, basestring):
                other_type = other
            else:
                return False
        else:
            try:
                pattern_compare(self.index, other_index)
            except ValueError:
                return False

        return pattern_compare(self.type, other_type, 1) == 0

    def __ne__(self, other):
        try:
            other_type = other.type
            other_index = other.index
        except AttributeError:
            if isinstance(other, basestring):
                other_type = other
            else:
                return True
        else:
            try:
                pattern_compare(self.index, other_index)
            except ValueError:
                return True

        return pattern_compare(self.type, other_type, 1) != 0

    def __gt__(self, other):
        try:
            other_type = other.type
            other_index = other.index
        except AttributeError:
            if isinstance(other, basestring):
                other_type = other
            else:
                return False
        else:
            try:
                pattern_compare(self.index, other_index)
            except ValueError:
                return False

        return pattern_compare(self.type, other_type, -1) == 1

    def __ge__(self, other):
        try:
            other_type = other.type
            other_index = other.index
        except AttributeError:
            if isinstance(other, basestring):
                other_type = other
            else:
                return False
        else:
            try:
                pattern_compare(self.index, other_index)
            except ValueError:
                return False

        return pattern_compare(self.type, other_type, -1) != -1


class FieldPattern(object):
    """FieldPattern container which provides methods to perform rich comparisons with other patterns.

    A pattern is either a simple string or an instance of FieldPattern. It's not possible to
    compare an instance of FieldPattern with an instance of IndexPattern or TypePattern.
    """

    def __init__(self, index_pattern, type_pattern, field_pattern):
        self.index = index_pattern
        self.type = type_pattern
        self.field = field_pattern

    def __str__(self):
        return self.field

    def __hash__(self):
        return hash((self.index, self.type, self.field))

    def __repr__(self):
        return "FieldPattern('{0}', '{1}', '{2}')".format(self.index, self.type, self.field)

    def __lt__(self, other):
        try:
            other_field = other.field
            other_type = other.type
            other_index = other.index
        except AttributeError:
            if isinstance(other, basestring):
                other_field = other
            else:
                return False
        else:
            try:
                pattern_compare(self.index, other_index)
                pattern_compare(self.type, other_type)
            except ValueError:
                return False

        return pattern_compare(self.field, other_field, 1) == -1

    def __le__(self, other):
        try:
            other_field = other.field
            other_type = other.type
            other_index = other.index
        except AttributeError:
            if isinstance(other, basestring):
                other_field = other
            else:
                return False
        else:
            try:
                pattern_compare(self.index, other_index)
                pattern_compare(self.type, other_type)
            except ValueError:
                return False

        return pattern_compare(self.field, other_field, 1) != 1

    def __eq__(self, other):
        try:
            other_field = other.field
            other_type = other.type
            other_index = other.index
        except AttributeError:
            if isinstance(other, basestring):
                other_field = other
            else:
                return False
        else:
            try:
                pattern_compare(self.index, other_index)
                pattern_compare(self.type, other_type)
            except ValueError:
                return False

        return pattern_compare(self.field, other_field, 1) == 0

    def __ne__(self, other):
        try:
            other_field = other.field
            other_type = other.type
            other_index = other.index
        except AttributeError:
            if isinstance(other, basestring):
                other_field = other
            else:
                return True
        else:
            try:
                pattern_compare(self.index, other_index)
                pattern_compare(self.type, other_type)
            except ValueError:
                return False

        return pattern_compare(self.field, other_field, 1) != 0

    def __gt__(self, other):
        try:
            other_field = other.field
            other_type = other.type
            other_index = other.index
        except AttributeError:
            if isinstance(other, basestring):
                other_field = other
            else:
                return False
        else:
            try:
                pattern_compare(self.index, other_index)
                pattern_compare(self.type, other_type)
            except ValueError:
                return False

        return pattern_compare(self.field, other_field, -1) == 1

    def __ge__(self, other):
        try:
            other_field = other.field
            other_type = other.type
            other_index = other.index
        except AttributeError:
            if isinstance(other, basestring):
                other_field = other
            else:
                return False
        else:
            try:
                pattern_compare(self.index, other_index)
                pattern_compare(self.type, other_type)
            except ValueError:
                return False

        return pattern_compare(self.field, other_field, -1) != -1
