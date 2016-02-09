# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

__all__ = ['format_ldap_error']


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
