# <a id="about"></a> About ElasticArmor

ElasticArmor is a HTTP reverse proxy placed in front of Elasticsearch to regulate access to its REST api. Authentication
can either be done by ElasticArmor itself or another reverse proxy placed in front of it. Authorization is done by
linking authenticated clients by their name or group memberships to roles. (Role Based Access Control)

REST api requests are regulated by inspecting the URL-Path, URL-Query and payload. Each role a client is associated
to defines what and how much is permitted in a particular index, document-type and field. Requests may be rewritten
by ElasticArmor if it's safe to do so without causing fundamental changes to a request's purpose. This also applies
to responses sent by Elasticsearch where ElasticArmor may inject its own error responses to avoid refusing an entire
request.

## <a id="about-installation"></a> Installation

ElasticArmor is written in Python and can run on versions 2.6 and 2.7. Package installation is not available.
Installing ElasticArmor from source is currently the only way.

See [here](02-Installation.md#installation) for how to install ElasticArmor.

## <a id="about-configuration"></a> Configuration

Once installed, ElasticArmor is able to run without any further configuration. There are proper defaults available
for all vital configuration directives. You will only need to actually configure ElasticArmor manually if those
defaults do not apply in your environment or if you want to use features that are not enabled by default.

See [here](03-Configuration.md#configuration) for how to configure ElasticArmor.

## <a id="about-authentication"></a> Authentication

By default ElasticArmor considers any request with basic authentication credentials as being authenticated. This
allows another reverse proxy being placed in front of ElasticArmor that is performing the actual authentication.
But it is also possible to have ElasticArmor performing the authentication by configuring one or more
authentication mechanisms.

See [here](04-Authentication.md#authentication) for how to configure authentication.

## <a id="about-usergroups"></a> Usergroups

A client is not only associated with roles by its name, but also by its group memberships. Group memberships can
be fetched by ElasticArmor independently from who is performing the authentication as long as the client has been
authenticated. (i.e. Group memberships cannot be fetched for anonymous requests)

See [here](05-Usergroups.md#usergroups) for how to configure usergroups.

## <a id="about-authorization"></a> Authorization

A client must be associated with at least a single role to successfully access the REST api. A role defines what the
permissions are a client has in a particular index, document-type and field. In case a client is associated with more
than a single role they are applied in a combined fashion so that the broadest access possible is granted.

See [here](06-Authorization.md#authorization) for how to configure authorization.

## <a id="about-integration"></a> Integration

Since ElasticArmor is designed to work as a gateway for all services accessing Elasticsearch,
their configuration must be adjusted so that they direct their requests to ElasticArmor instead.

See [here](07-Integration.md#integration) for some examples on how to properly integrate ElasticArmor.

## <a id="about-limitations"></a> Limitations

ElasticArmor is highly dependent on the filter capabilities of Elasticsearch's REST api and may or may not be
compatible with a particular version of Elasticsearch. You should be aware of these limitations to not to
accidentally make any mistakes that will compromise security.

See [here](08-Limitations.md#limitations) to learn more about what ElasticArmor is not capable of and why.
