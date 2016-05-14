# <a id="usergroups"></a> Usergroups

The usergroup configuration is located in `/etc/elasticarmor/groups.ini`.

ElasticArmor can optionally fetch a client's usergroups from multiple so called backends. Note that this only works
for authenticated clients, anonymous clients cannot be group members. However, it does not matter who performed the
authentication.

Each backend has a name which is also the name of the INI section. The type of backend is denoted by the option
*backend* and may be followed by backend-specific options.

The following types of usergroup backends are currently supported:

## <a id="usergroups-ldap"></a> Ldap

To fetch usergroups by using Ldap, use the following options to define where and as who to connect:

Option  | Description
--------|----------------------------------------------------------------------------------------
url     | ldap://example.org, ldaps://example.org:636 (SSL) or ldaps://example.org:389 (STARTTLS)
bind_dn | The distinguished name to use when binding to the ldap server
bind_pw | The password to use when binding to the ldap server

The next options define where to locate groups and how to associate them with users:

Option                      | Description
----------------------------|-------------------------------------------------------------
user_base_dn                | The base dn where to search for users
user_object_class           | The object class of a user
user_name_attribute         | The name of the attribute where a user's name is stored
group_base_dn               | The base dn where to search for groups
group_object_class          | The object class of a group
group_name_attribute        | The name of the attribute where a group's name is stored
group_membership_attribute  | The name of the attribute where a group's members are stored

The remaining options listed below can be additionally set to customize usergroup retrieval:

Option              | Description
--------------------|----------------------------------------------------------------------------------
user_object_filter  | A native search filter used to limit the set of users for which to provide groups
group_object_filter | A native search filter used to limit the available set of groups

### <a id="usergroups-ldap-ad"></a> ActiveDirectory

If you want to authenticate clients by using ActiveDirectory, you can use the `msldap` type to utilize
the following default values:

Option                      | Default
----------------------------|--------------------------------
user_object_class           | user
user_name_attribute         | sAMAccountName
group_object_class          | group
group_name_attribute        | sAMAccountName
group_membership_attribute  | member:1.2.840.113556.1.4.1941:

### <a id="usergroups-ldap-example"></a> Example

ActiveDirectory usergroup backend:

    [example_ad]
    backend="msldap"
    url="ldaps://example.org:389"
    bind_dn="cn=elasticarmor,ou=services,dc=example,dc=org"
    bind_pw="p@ssw0rd"
    user_base_dn="ou=people,dc=example,dc=org"
    group_base_dn="ou=groups,dc=example,dc=org"
