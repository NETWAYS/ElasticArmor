# <a id="integration"></a> Integration

## <a id="integration-elasticsearch"></a> Elasticsearch

You can connect ElasticArmor to any node in your Elasticsearch cluster if you use the default settings of Elasticsearch.
By default every node holds parts of the data and the master is automatically chosen from all available nodes. Every
node can be queried and will automatically forward requests to the nodes holding the corresponding shards.

### <a id="integration-elasticsearch-client-node"></a> Client Node

Client nodes are essentially routers which forward cluster- and data-requests to other nodes as needed. The common
use-case with ElasticArmor is to install a dedicated client node on the same host so that this node can take off
load from the actual master- and data-nodes.

To turn an Elasticsearch node into a client node, add the following lines to your `elasticsearch.yml`:

    node.master: false
    node.data: false

See [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-node.html#modules-node)
for more information.

### <a id="integration-elasticsearch-master-node"></a> Master Node

Elasticsearch allows to configure nodes to act only as master. Running dedicated data nodes and master nodes may
provide some stability benefit in large clusters. However, configuring ElasticArmor to query master-only nodes is
**not** recommended as this contradicts the sole purpose of
[such a node](https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-node.html#master-node).

If you run an Elasticsearch cluster with default settings for `node.master` where all nodes are potential master
nodes and a master is chosen among them, there is nothing wrong with ElasticArmor connecting to the current master.

## <a id="integration-services"></a> Services

ElasticArmor is designed to be placed in front of Elasticsearch and act as gateway for all incoming requests to its
REST api. While integrating ElasticArmor into your infrastructure you should ensure that this is actually the case
because otherwise it will still be possible to direct requests at Elasticsearch effectively bypassing ElasticArmor.

> **Note:**
>
> Example role configurations shown below are encoded with YAML for better readability. However, Elasticsearch does
> only accept JSON encoded configuration when indexing or updating roles. You can find their JSON counterparts in
> the [examples/](examples/) directory instead.

### <a id="integration-services-kibana"></a> Kibana

To regulate Kibana users using ElasticArmor, it is required to make Kibana direct all REST api requests
[to ElasticArmor instead of Elasticsearch](https://www.elastic.co/guide/en/kibana/current/setup.html#connect).

#### <a id="integration-services-kibana-user"></a> Kibana User Example

Kibana stores its content configuration in an index called *.kibana* by default. An example
role that grants full access to it and read only access to all other indices is shown below:

```yaml
privileges:
  cluster:
    - api/bulk
    - api/cluster/nodes/info
  indices:
    - include: *
      exclude: .kibana*
      permissions:
        - api/indices/get/*
        - api/search/documents
    - include: .kibana*
      permissions:
        - api/cluster/health
        - api/indices/refresh
        - api/indices/create/index
        - api/indices/create/mapping
        - api/indices/get/mapping
        - api/documents/get
        - api/documents/index
        - api/documents/delete
        - api/documents/update
        - api/search/documents
        - api/search/explain
```

> **Note:**
>
> Kibana 3 utilizes the [facets](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-facets.html)
> feature of Elasticsearch, that is deprecated and removed in version 2.x. ElasticArmor does not inspect faceted
> searches and thus cannot enforce field restrictions in this case. To allow faceted searches use the
> `api/feature/facets` permission.

#### <a id="integration-services-kibana-server"></a> Kibana Server Example

Since version 4, Kibana provides its own web-server and may issue REST api requests on its own.
An example role that grants the required access to the *.kibana* index is shown below:

```yaml
privileges:
  cluster:
    - api/bulk
    - api/cluster/nodes/info
  indices:
    - include: .kibana
      permissions:
        - api/cluster/health
        - api/indices/refresh
        - api/indices/create/index
        - api/indices/create/mapping
        - api/indices/get/mapping
        - api/documents/get
        - api/documents/index
        - api/documents/delete
        - api/documents/update
        - api/search/documents
        - api/search/explain
```

> **Note:**
>
> Prior version 4.5 Kibana cannot send authentication credentials for such requests. You will need to enable
> [anonymous access](03-Configuration.md#configuration-proxy-anonymous-access) for the host the web-server is
> running on to permit them.
