# <a id="limitations"></a> Limitations

## <a id="limitations-compatibility"></a> Compatibility

As already mentioned, ElasticArmor is highly dependent on the functionality provided by Elasticsearch's REST api. For
this reason, ElasticArmor will check the version of each configured node and spits out a warning in the log if there
is a node with an incompatible version. Feature-wise discrepancies are usually not an issue other than that you may
not be able to utilize new or removed features. Though, changes in functionality can be a serious issue in case this
means that features that were previously considered being not security relevant now are. Thus you will need to take
extra care when upgrading to any new version of Elasticsearch.

The following versions are currently supported:

* 1.7.x

## <a id="limitations-cluster-communication"></a> Cluster Communication

ElasticArmor can only regulate clients accessing one entry point of your cluster. If you have got multiple entry
points you will also need to setup multiple instances of ElasticArmor. Though, what is happening *inside* the
cluster is a completely different matter as ElasticArmor cannot secure the communication of the cluster nodes.
You need to either wrap your cluster with a security perimeter or install a plugin on each node which is capable
of encrypting the communication.

## <a id="limitations-inspection"></a> Request Inspection

ElasticArmor is very strict if it is about inspecting requests. This starts at how to disassemble and interpret a
request's URL and does not stop until it knows about the exact purpose of each and every byte that is part of the
payload. However, ElasticArmor is not omniscient.

### <a id="limitations-inspection-on-track"></a> Keeping on Track with Elasticsearch

Every new version of Elasticsearch may introduce new features. These features may or may not be security relevant,
but ElasticArmor needs to know their exact purpose to decide when to apply restrictions or check permissions. So
once a new version of Elasticsearch has been released it is unlikely that you can instantly utilize every new
feature without waiting for an updated version of ElasticArmor.

### <a id="limitations-inspection-coverage"></a> Coverage of REST API Endpoints

There are still (luckily) human beings responsible for ElasticArmor. And such a being lives a life that is not
entirely for free (unfortunately) and cannot invest all of its daytime to fully cover Elasticsearch's REST api.
And it is really *huge*, especially in terms of depth. We have started developing ElasticArmor just this year,
so there are some functionalities where you can regulate the who and mostly the where, but not the what, yet.

These functionalities currently include the following:

* [Query String Query](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html)
    * No inspection. Requires the `api/feature/queryString` permission.
      For compatibility reasons with Kibana, `*` does not require it.
* [Inner hits](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-inner-hits.html)
    * No inspection of any kind is being applied. Requires the `api/feature/innerHits` permission.
* [Bulk API](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html)
    * No inspection and rewriting of any kind is being applied.
      Additionally requires the `api/feature/notImplemented` permission.
* [Term Vectors](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-termvectors.html)
    * No URL-Query and payload inspection. No rewriting.
* [Multi termvectors API](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-multi-termvectors.html)
    * No payload inspection. No rewriting.
* [Search Shards API](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-shards.html)
    * No rewriting.
* [Suggesters](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-suggesters.html)
    * No payload inspection.
* [Count API](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-count.html)
    * No URL-Query and payload inspection. No rewriting.
* [Search Exists API](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-exists.html)
    * No URL-Query and payload inspection. No rewriting.
* [Explain API](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-explain.html)
    * No URL-Query and payload inspection.
* [Percolator](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-percolate.html)
    * No URL-Query and payload inspection.
* [Field stats API](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-field-stats.html)
    * No URL-Query and payload inspection. No rewriting.
* [Index Aliases](https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-aliases.html)
    * No URL-Query and payload inspection. No rewriting.
* [Warmers](https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-warmers.html)
    * No rewriting.
* [Indices Stats](https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-stats.html)
    * No URL-Query inspection. No rewriting.
* [cat APIs](https://www.elastic.co/guide/en/elasticsearch/reference/current/cat.html)
    * **Attention:** This is currently a cluster-wide permission.
      No inspection and rewriting of any kind is being applied.

### <a id="limitations-inspection-for-search"></a> You Know, for Search

Elasticsearch is more than just a simple document oriented database. Its purpose is to provide efficient and powerful
tools to analyze and search data. Some of these tools are that much powerful, that they are difficult to tame, even
for ElasticArmor. With ElasticArmor, you can regulate the who and where, but not the what.

These tools currently include the following:

* [Scripting](https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-scripting.html)
* [Search Template](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-template.html)
* [More Like This API](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-more-like-this.html)
* [More Like This Query](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-mlt-query.html)
* [Fuzzy Like This Query](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-flt-query.html)

### <a id="limitations-inspection-multi"></a> Multi index, Multi type

When accessing endpoints with support for multiple indices and types, such as the Search-API, ElasticArmor may challenge
you to choose a single index and type. This happens if you are restricted to specific types or fields and is required
because ElasticArmor cannot (as of today) instruct Elasticsearch to apply filters only to particular indices or types.

### <a id="limitations-inspection-fields"></a> Fields and Excludes

The [fields](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-fields.html) parameter
does not support excludes. Every field restriction that contains excludes can therefore not be applied in this case.
This may lead to less fields being returned than you are allowed to access. Use
[source filtering](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-source-filtering.html)
instead. Or avoid being assigned to roles with field-excludes.
