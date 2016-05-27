# <a id="authentication"></a> Authentication

The authentication configuration is located in `/etc/elasticarmor/authentication.ini`.

In case you want ElasticArmor to authenticate clients, you have the possibility to accomplish this with multiple so
called backends. If multiple backends are configured, a client has authenticated itself once one of them succeeded
with the authentication.

A role can be defined for each backend which will then act as default role for all clients for which authentication
has succeeded. To define a default role simply configure it as usual and set its name on a backend by using the
option *default_role*.

Each backend has a name which is also the name of the INI section. The type of backend is denoted by the option
*backend* and may be followed by backend-specific options.

    [<name>]
    backend=<type>

The following types of authentication backends are currently supported:

## <a id="authentication-elasticsearch"></a> Elasticsearch

Once configured ElasticArmor will look up users in the Elasticsearch index `.elasticarmor` and tries to authenticate
a client using the stored credentials.

Users are stored as documents of type `user` using their name as id and the following properties:

Property      | Description
--------------|------------------------------------------------------
password_hash | A salted and hashed password as base64 encoded string

An example on how to create a new user called *jdoe* with the password *p@ssw0rd*:

```shell
curl -XPOST localhost:9200/.elasticarmor/user/jdoe -d '{"password_hash": "JDEkZ0hLUlFqSW0kbDFxS2pTM0JYUVhwaVpzdnQ0MVh6MA=="}'
```

For more information on how to manage documents please take a look at the
[documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs.html).

### <a id="authentication-elasticsearch-hashing"></a> Hashing Passwords

The backend currently supports only the MD5-based password algorithm. You can use the following to hash passwords:

```shell
openssl passwd -1 p@ssw0rd | tr -d '\n' | base64
```

## <a id="authentication-ldap"></a> Ldap

To authenticate clients by using Ldap, use the following options to define where and as who to connect:

Option  | Description
--------|----------------------------------------------------------------------------------------
url     | ldap://example.org, ldaps://example.org:636 (SSL) or ldaps://example.org:389 (STARTTLS)
bind_dn | The distinguished name to use when binding to the ldap server
bind_pw | The password to use when binding to the ldap server

The next options define where to locate users and how to associate usernames with distinguished names:

Option              | Description
--------------------|--------------------------------------------------------
user_base_dn        | The base dn where to search for users
user_object_class   | The object class of a user
user_name_attribute | The name of the attribute where a user's name is stored

The remaining options listed below can be additionally set to customize authentication:

Option              | Description
--------------------|---------------------------------------------------------------------------
user_object_filter  | A native search filter used to limit the set of users able to authenticate

### <a id="authentication-ldap-ad"></a> ActiveDirectory

If you want to authenticate clients by using ActiveDirectory, you can use the `msldap` type to utilize
the following default values:

Option              | Default
--------------------|---------------
user_object_class   | user
user_name_attribute | sAMAccountName

### <a id="authentication-ldap-example"></a> Example

ActiveDirectory authentication backend:

    [example_ad]
    backend="msldap"
    url="ldaps://example.org:389"
    bind_dn="cn=elasticarmor,ou=services,dc=example,dc=org"
    bind_pw="p@ssw0rd"
    user_base_dn="ou=people,dc=example,dc=org"
    default_role="people"
