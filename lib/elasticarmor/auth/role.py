# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

import operator

from elasticarmor.auth import AuthorizationError
from elasticarmor.util import pattern_compare
from elasticarmor.util.elastic import ElasticRole

__all__ = ['RoleError', 'RestrictionsFound', 'Role', 'RestrictionError', 'Restriction', 'Pattern']


class RoleError(AuthorizationError):
    """Raised by class Role in case of an error."""
    pass


class RestrictionsFound(Exception):
    """Raised by method Role.get_restrictions() to indicate that restrictions
    were found but none of them grant the required permission.

    """
    pass


class Role(ElasticRole):
    @property
    def _privileges(self):
        try:
            return self.__privileges
        except AttributeError:
            # TODO: Type checks! Elasticsearch does not analyze the privileges anymore!
            cluster, indices, types, fields = [], [], [], []
            if self.privileges.get('cluster'):
                cluster = self.privileges['cluster']

            if self.privileges.get('indices'):
                for index_data in self.privileges['indices']:
                    index_restriction = Restriction.from_json(index_data)
                    indices.append(index_restriction)
                    if index_data.get('types'):
                        for type_data in index_data['types']:
                            type_restriction = Restriction.from_json(type_data, index_restriction)
                            types.append(type_restriction)
                            if type_data.get('fields'):
                                for field_data in type_data['fields']:
                                    fields.append(Restriction.from_json(field_data, type_restriction))

            if self.privileges.get('types'):
                if not indices:
                    raise RoleError(
                        'Role "{0}" defines type restrictions but not any index restrictions'.format(self.id))

                for type_data in self.privileges['types']:
                    for index_restriction in indices:
                        type_restriction = Restriction.from_json(type_data, index_restriction)
                        types.append(type_restriction)
                        if type_data.get('fields'):
                            for field_data in type_data['fields']:
                                fields.append(Restriction.from_json(field_data, type_restriction))

            if self.privileges.get('fields'):
                if not types:
                    raise RoleError(
                        'Role "{0}" defines field restrictions but not any type restrictions'.format(self.id))

                for field_data in self.privileges['fields']:
                    for type_restriction in types:
                        fields.append(Restriction.from_json(field_data, type_restriction))

            if not cluster and not indices and not types and not fields:
                raise RoleError('Role "{0}" does not define any privileges'.format(self.id))

            self.__privileges = {'cluster': cluster, 'indices': indices, 'types': types, 'fields': fields}
            return self.__privileges

    def get_restricted_scope(self):
        """Return the smallest scope this role has restrictions for.
        That's either None, 'indices', 'types' or 'fields'.

        """
        if self._privileges['fields']:
            return 'fields'
        elif self._privileges['types']:
            return 'types'
        elif self._privileges['indices']:
            return 'indices'

    def get_restrictions(self, index=None, document_type=None, permission=None, invert=False):
        """Return all restrictions for the given context which do or do not grant the given permission.
        Climbs up the entire privilege hierarchy in case a restriction inherits permissions
        until a partially matching parent is found that grants the permission.

        Raises RestrictionsFound in case a permission is given, invert is False and restrictions
        were found but none of them grant the required permission.
        """
        restrictions, candidates, restrictions_found = [], [], False
        if document_type is not None:
            pattern = Pattern.from_context(index, document_type)
            for restriction in self._privileges['fields']:
                if restriction.matches(pattern):
                    if permission is None:
                        # If there is no permission it's the restriction itself we're interested in
                        restrictions.append(restriction)
                    elif not restriction.permissions:
                        # Restrictions without any permissions are considered inheriting
                        candidates.append(restriction)
                    elif not invert:
                        restrictions_found = True
                        # Whereas restrictions with at least one permission
                        # are required to match and if not, are ignored...
                        if any(self._match_permissions(permission, p) for p in restriction.permissions):
                            restrictions.append(restriction)
                    elif invert and not any(self._match_permissions(permission, p) for p in restriction.permissions):
                        # ...unless we're inverting the match, of course
                        restrictions.append(restriction)

            if not candidates:
                # Stop here in case there are not any remaining candidates as there is nothing else to collect
                if restrictions_found and not restrictions:
                    # There were matching restrictions, but none of them grant
                    # the required permission, so signal this to the caller
                    raise RestrictionsFound()

                return restrictions

        if index is not None and (not restrictions or candidates):
            if candidates:
                # If there are already candidates, ensure that these are not touched and
                # use a pattern that represents the full context to avoid false-positives
                register_candidates = False
                pattern = Pattern.from_context(index, document_type)
            else:
                register_candidates = True
                pattern = Pattern.from_context(index)

            for restriction in self._privileges['types']:
                if restriction.matches(pattern):
                    if permission is None:
                        restrictions.append(restriction)
                    elif not restriction.permissions:
                        if register_candidates:
                            candidates.append(restriction)
                    elif not invert:
                        if register_candidates:
                            restrictions_found = True

                        if any(self._match_permissions(permission, p) for p in restriction.permissions):
                            if register_candidates:
                                # Avoid touching the restrictions as well, since we're
                                # interested in the remaining candidates only
                                restrictions.append(restriction)
                            elif candidates:
                                # Any matching parent allows to include the remaining
                                # candidates in the final result, at once
                                restrictions.extend(candidates)
                                return restrictions
                    elif invert:
                        if any(self._match_permissions(permission, p) for p in restriction.permissions):
                            if not register_candidates and candidates:
                                # The restriction obviously grants the permission and since that's not
                                # what we're out for in case the match is inverted it means that all
                                # remaining candidates now have it as well and as such are obsolete
                                return restrictions
                        elif register_candidates:
                            restrictions.append(restriction)
                        elif candidates:
                            # In case of a failed inverted match and remaining candidates
                            # we'll stop at the first parent that is not inheriting as well
                            restrictions.extend(candidates)
                            return restrictions

            if not candidates:
                if restrictions_found and not restrictions:
                    raise RestrictionsFound()

                return restrictions

        if not restrictions or candidates:
            if candidates:
                register_candidates = False
                pattern = Pattern.from_context(index)
            else:
                register_candidates = True
                pattern = None

            for restriction in self._privileges['indices']:
                if pattern is None or restriction.matches(pattern):
                    if permission is None:
                        restrictions.append(restriction)
                    elif not restriction.permissions:
                        if register_candidates:
                            restrictions.append(restriction)
                    elif not invert:
                        if register_candidates:
                            restrictions_found = True

                        if any(self._match_permissions(permission, p) for p in restriction.permissions):
                            if register_candidates:
                                restrictions.append(restriction)
                            elif candidates:
                                restrictions.extend(candidates)
                                return restrictions
                    elif invert:
                        if any(self._match_permissions(permission, p) for p in restriction.permissions):
                            if not register_candidates and candidates:
                                return restrictions
                        elif register_candidates:
                            restrictions.append(restriction)
                        elif candidates:
                            restrictions.extend(candidates)
                            return restrictions

        if candidates:
            if not invert:
                if any(self._match_permissions(permission, p) for p in self._privileges['cluster']):
                    restrictions.extend(candidates)
            elif not any(self._match_permissions(permission, p) for p in self._privileges['cluster']):
                restrictions.extend(candidates)

        if restrictions_found and not restrictions:
            raise RestrictionsFound()

        # TODO: Return a generator instead
        return restrictions

    def permits(self, permission, index=None, document_type=None, field=None):
        """Return whether this role permits the given permission in the given context.
        May return True if the permission has been granted at a higher level.

        """
        if field is not None:
            field_match = self._grants_permission(permission, self.get_restrictions(index, document_type),
                                                  Pattern.from_context(index, document_type, field))
            if field_match is not None:
                return field_match

        if document_type is not None:
            type_match = self._grants_permission(permission, self.get_restrictions(index),
                                                 Pattern.from_context(index, document_type))
            if type_match is not None:
                return type_match

        if index is not None:
            index_match = self._grants_permission(permission, self.get_restrictions(),
                                                  Pattern.from_context(index))
            if index_match is not None:
                return index_match

        return any(self._match_permissions(permission, p) for p in self._privileges['cluster'])

    def _grants_permission(self, permission, privileges, pattern=None):
        """Helper for method permit()."""
        if not privileges:
            return

        check_parents = False
        for restriction in privileges:
            if pattern is None or restriction.matches(pattern):
                if not restriction.permissions:
                    check_parents = True
                elif any(self._match_permissions(permission, p) for p in restriction.permissions):
                    return True

        return None if check_parents else False

    @staticmethod
    def _match_permissions(required, granted):
        """Return whether the given granted permission matches the given required permission."""
        if granted == '*':
            return True
        elif not required.endswith('/*'):
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

    def __init__(self, includes, excludes=None, permissions=None, parent=None):
        self.permissions = permissions or []
        self.excludes = excludes or []
        self.includes = includes
        self.parent = parent

    def __repr__(self):
        return 'Restriction({0!r}, {1!r}, {2!r}, {3!r})' \
               ''.format(self.includes, self.excludes, self.permissions, self.parent)

    def __eq__(self, other):
        try:
            other_parent = other.parent
            other_includes = other.includes
            other_excludes = other.excludes
        except AttributeError:
            return False

        for my_include, other_include in ((mi, oi) for mi in self.includes for oi in other_includes):
            try:
                pattern_compare(str(my_include), str(other_include))
            except ValueError:
                pass
            else:
                if not any(other_exclude >= my_include for other_exclude in other_excludes):
                    break

                return False
        else:
            return False

        return self.parent == other_parent

    @classmethod
    def from_json(cls, data, parent=None):
        """Create and return a new instance of Restriction using the given JSON data."""
        type_restriction = field_restriction = False
        if parent is not None:
            if parent.parent is None:
                type_restriction = True
            else:
                field_restriction = True

        try:
            raw_includes = data.get('include', '').split(',')
        except AttributeError:
            raw_includes = data.get('include', [])
            if not isinstance(raw_includes, list):
                raise RestrictionError('Invalid value for key "include" of restriction "{0!r}"'.format(data))

        includes = []
        for pattern in filter(None, (p.strip() for p in raw_includes)):
            if type_restriction and '*' in pattern:
                raise RestrictionError('Type includes with wildcards are not supported'
                                       ' ("{0}")'.format(pattern))
            elif field_restriction and len(pattern) > 1 and pattern.startswith('*'):
                raise RestrictionError('Field includes with leading wildcards are not supported'
                                       ' ("{0}")'.format(pattern))

            includes.append(Pattern(pattern, parent))

        if not includes:
            raise RestrictionError('Restriction "{0}" does not provide any includes'.format(data))

        try:
            # TODO: Don't parse excludes for type restrictions
            raw_excludes = data.get('exclude', '').split(',')
        except AttributeError:
            raw_excludes = data.get('exclude', [])
            if not isinstance(raw_excludes, list):
                raise RestrictionError('Invalid value for key "exclude" of restriction "{0!r}"'.format(data))

        excludes = []
        for pattern in filter(None, (p.strip() for p in raw_excludes)):
            if type_restriction and '*' in pattern:
                raise RestrictionError('Type excludes with wildcards are not supported'
                                       ' ("{0}")'.format(pattern))
            elif field_restriction and len(pattern) > 1 and pattern.startswith('*'):
                raise RestrictionError('Field excludes with leading wildcards are not supported'
                                       ' ("{0}")'.format(pattern))

            excludes.append(Pattern(pattern, parent))

        try:
            raw_permissions = data.get('permissions', '').split(',')
        except AttributeError:
            raw_permissions = data.get('permissions', [])
            if not isinstance(raw_permissions, list):
                raise RestrictionError('Invalid value for key "permissions" in restriction "{0!r}"'.format(data))

        return cls(includes, excludes, filter(None, (permission.strip() for permission in raw_permissions)), parent)

    def matches(self, pattern, op=operator.le):
        """Return whether the given pattern matches this restriction."""
        return any(op(pattern, include) for include in self.includes) and \
            not any(exclude >= pattern for exclude in self.excludes)


# TODO: Comments. This is way too much magic to remain uncommented...
class Pattern(object):
    """Pattern container which provides methods to perform rich comparisons with other patterns."""

    def __init__(self, pattern, parent=None):
        self.pattern = str(pattern)
        self.parent = parent

    def __str__(self):
        return self.pattern

    def __hash__(self):
        return hash(self.pattern)

    def __repr__(self):
        return 'Pattern({0!r}, {1!r})'.format(self.pattern, self.parent)

    @classmethod
    def from_context(cls, index, document_type=None, field=None):
        """Create and return a new instance of Pattern using the given context."""
        pattern = cls(index)
        if document_type is not None:
            index_restriction = Restriction([pattern])
            pattern = cls(document_type, parent=index_restriction)
            if field is not None:
                pattern = cls(field, parent=Restriction([pattern], parent=index_restriction))

        return pattern

    def _compare(self, other, op, incompatible=False):
        try:
            other_parent = other.parent
            other_pattern = other.pattern
        except AttributeError:
            try:
                return op(pattern_compare(self.pattern, str(other)), 0)
            except ValueError:
                return incompatible

        native = False
        if self.parent is None:
            if other_parent is None:
                native = True
        elif self.parent.parent is None:
            if other_parent is None:
                return incompatible
            elif other_parent.parent is None:
                native = True
        elif other_parent is None or other_parent.parent is None:
            return incompatible
        else:
            native = True

        if not native:
            return other_parent.matches(self, op)

        try:
            return op(pattern_compare(self.pattern, other_pattern), 0) and self.parent == other_parent
        except ValueError:
            return incompatible

    def __lt__(self, other):
        return self._compare(other, operator.lt)

    def __le__(self, other):
        return self._compare(other, operator.le)

    def __eq__(self, other):
        return self._compare(other, operator.eq)

    def __ne__(self, other):
        return self._compare(other, operator.ne, True)

    def __gt__(self, other):
        return self._compare(other, operator.gt)

    def __ge__(self, other):
        return self._compare(other, operator.ge)
