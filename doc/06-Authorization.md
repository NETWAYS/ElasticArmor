# <a id="authorization"></a> Authorization

Clients are authorized using roles.

* A role can be assigned to multiple users and to multiple groups and vice versa.
* A role defines privileges which grant particular permissions on the index, document-type and field level.
* Privileges from multiple roles are applied in a combined fashion and cannot restrict one another.

## <a id="authorization-users-and-groups"></a> Users and Groups

Users and groups are assigned to roles using their name.

> **Note:**
>
> For [anonymous clients](03-Configuration.md#configuration-proxy-anonymous-access), this is the name of the host.

## <a id="authorization-privileges"></a> Privileges

Privileges consist of the following scopes:

* cluster
* indices
* types
* fields

For the cluster scope you can only define permissions, whereas for all other scopes you define restrictions.

### <a id="authorization-privileges-restrictions"></a> Restrictions

A restriction consists of includes, excludes and permissions. Depending on the scope you have several ways to define
includes and excludes.

> **Note:**
>
> Restrictions will inherit permissions from their parent scope, if they do not define any permissions by themselves.

#### <a id="authorization-privileges-restrictions-indices"></a> Index Restrictions

Index in- and excludes can be defined using patterns with one or more optional `*` wildcards.

#### <a id="authorization-privileges-restrictions-types"></a> Type Restrictions

Type restrictions only support includes by explicit names. No wildcards.

#### <a id="authorization-privileges-restrictions-fields"></a> Field Restrictions

Field restrictions are much like index restrictions, except that they **must not** have a leading `*` wildcard.

### <a id="authorization-privileges-permissions"></a> Permissions

Permissions are divided into namespaces separated by a slash `/`. To grant an entire namespace you can use the `*`
wildcard instead.

#### <a id="authorization-privileges-permissions-config"></a> Config Permissions

ElasticArmor allows to store some of its configuration in Elasticsearch itself. To access
the index and its configuration one of the following cluster-wide permissions is required:

Permission Name         | Configuration Type
------------------------|-------------------
config/authorization    | Roles

#### <a id="authorization-privileges-permissions-api"></a> API Permissions

Each permission in the table below has a scope assigned to it. This is the smallest scope a permission can be
granted to. This means that permissions can also be granted in a bigger scope, causing a permission to apply
to all restrictions defined in the lower scopes, if they are able to inherit permissions.

Permission Name                 | Applies to Scope
--------------------------------|-----------------
api/cluster/health              | indices
api/cluster/state               | cluster
api/cluster/stats               | cluster
api/cluster/pendingTasks        | cluster
api/cluster/reroute             | cluster
api/cluster/get/settings        | cluster
api/cluster/update/settings     | cluster
api/cluster/nodes/stats         | cluster
api/cluster/nodes/info          | cluster
api/cluster/nodes/hotThreads    | cluster
api/cluster/nodes/shutdown      | cluster
api/indices/create/index        | indices
api/indices/delete/index        | indices
api/indices/open                | indices
api/indices/close               | indices
api/indices/create/mappings     | types
api/indices/delete/mappings     | types
api/indices/get/mappings        | types
api/indices/create/aliases      | indices
api/indices/delete/aliases      | indices
api/indices/get/aliases         | indices
api/indices/update/settings     | indices
api/indices/get/settings        | indices
api/indices/analyze             | indices
api/indices/create/templates    | cluster
api/indices/delete/templates    | cluster
api/indices/get/templates       | cluster
api/indices/create/warmers      | indices
api/indices/delete/warmers      | indices
api/indices/get/warmers         | indices
api/indices/stats               | indices
api/indices/segments            | indices
api/indices/recovery            | indices
api/indices/cache/clear         | indices
api/indices/flush               | indices
api/indices/refresh             | indices
api/indices/optimize            | indices
api/indices/upgrade             | indices
api/documents/index             | types
api/documents/get               | fields
api/documents/delete            | types
api/documents/update            | fields
api/documents/deleteByQuery     | types
api/documents/termVector        | types
api/search/documents            | fields
api/search/templates            | cluster
api/search/shards               | indices
api/search/suggest              | cluster
api/search/explain              | types
api/search/percolate            | types
api/search/fieldStats           | indices
api/cat                         | cluster
api/bulk                        | cluster
api/feature/deprecated          | cluster
api/feature/facets              | types
api/feature/fuzzyLikeThis       | types
api/feature/innerHits           | types
api/feature/moreLikeThis        | types
api/feature/notImplemented      | types
api/feature/queryString         | types
api/feature/script              | types

While the purpose of most of the permissions above should be clear, as they are very similar structured to how
Elasticsearch's REST api is, you may wonder what these permissions in the feature namespace are for. They look
different to all others and seem to have a special purpose and that is exactly what is intended.

Feature permissions should be granted with care. They are used to protect parts of Elasticsearch's REST api which
are not regulated by ElasticArmor to the same extent as the others are. Granting such a permission will most likely
allow a client to freely access data or perform write operations. Below are some more details about those feature
permissions.

##### <a id="authorization-privileges-permissions-bulk"></a> api/bulk

Required for all bulk operations such as:

* [Bulk API](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html)
* [Multi Get API](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-multi-get.html)
* [Multi termvectors API](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-multi-termvectors.html)
* [Multi Search API](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-multi-search.html)
* [Multi Percolate API](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-percolate.html#_multi_percolate_api)

##### <a id="authorization-privileges-permissions-feature-deprecated"></a> api/feature/deprecated

Required for api endpoints which are deprecated, not fully inspected and where it is unlikely that the missing
functionality will be added. These include:

* [Delete By Query API](https://www.elastic.co/guide/en/elasticsearch/reference/1.7/docs-delete-by-query.html)
* [More Like This API](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-more-like-this.html)
* [Nodes Shutdown](https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-nodes-shutdown.html)

##### <a id="authorization-privileges-permissions-feature-facets"></a> api/feature/facets

Required for [faceted](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-facets.html)
searches because they are not inspected and will never be, as they have been replaced by
[aggregations](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-aggregations.html).

##### <a id="authorization-privileges-permissions-feature-fuzzyLikeThis"></a> api/feature/fuzzyLikeThis

Required for the [Fuzzy Like This Query](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-flt-query.html)
and the [Fuzzy Like This Field Query](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-flt-field-query.html).

##### <a id="authorization-privileges-permissions-feature-innerHits"></a> api/feature/innerHits

Required for [inner hits](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-inner-hits.html)
because they are not inspected yet. Expect this permission to fade out in the future once the missing functionality has
been added.

##### <a id="authorization-privileges-permissions-feature-moreLikeThis"></a> api/feature/moreLikeThis

Required for the [More Like This API](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-more-like-this.html)
and the [More Like This Query](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-mlt-query.html).

##### <a id="authorization-privileges-permissions-feature-notImplemented"></a> api/feature/notImplemented

Required for api endpoints which are not yet fully inspected, but their functionality is partly implemented for other
endpoints. These include:

* [Bulk API](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html)
* [Explain API](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-explain.html)

Expect this permission to fade out in the future once the missing functionality has been added.

##### <a id="authorization-privileges-permissions-feature-queryString"></a> api/feature/queryString

Required for [query string](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html)
searches because they are not inspected yet. For compatibility reasons with Kibana, `*` does not require it. Expect
this permission to fade out in the future once the missing functionality has been added.

##### <a id="authorization-privileges-permissions-feature-script"></a> api/feature/script

Required for [scripting](https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-scripting.html).


## <a id="authorization-configuration"></a> Configuration

ElasticArmor currently supports only one way to configure roles: The Elasticsearch index `.elasticarmor`  
This index is created on the first run using the following settings and mappings:

```json
{
  "settings": {
    "analysis": {
      "analyzer": {
        "lowercase_keyword": {
          "type": "custom",
          "filter": "lowercase",
          "tokenizer": "keyword"
        }
      }
    }
  },
  "mappings": {
    "role": {
      "properties": {
        "users": {
          "type": "string",
          "analyzer": "lowercase_keyword"
        },
        "groups": {
          "type": "string",
          "analyzer": "lowercase_keyword"
        },
        "privileges": {
          "type": "object",
          "enabled": false
        }
      }
    }
  }
}
```

A simple example on how to create or update a role:

```shell
curl -XPOST localhost:9200/.elasticarmor/role/kibana-user -d @examples/kibana-user.json
```

For more information on how to manage roles please take a look at the
[documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs.html).
