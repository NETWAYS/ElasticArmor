# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

from elasticarmor import APP_NAME
from elasticarmor.auth import MultipleIncludesError
from elasticarmor.request import *
from elasticarmor.util.elastic import SourceFilter


class IndexApiRequest(ElasticRequest):
    locations = {
        'POST': '/{index}/{document}',
        'PUT': [
            '/{index}/{document}/{identifier}',
            '/{index}/{document}/{identifier}/_create'
        ]
    }

    def inspect(self, client):
        # TODO: Check if it's required to validate a parent's id (Whether the client has access to the parent's type)
        if not client.can('api/documents/index', self.index, self.document):
            raise PermissionError('You are not permitted to index documents of this type in the given index.')
        elif client.has_restriction(self.index, self.document):
            raise PermissionError('You are restricted to specific fields of the given type.'
                                  ' Please use the update api instead.')
        elif not self.query.is_false('refresh') and not client.can('api/indices/refresh', self.index):
            raise PermissionError('You are not permitted to refresh this index.')


class GetApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/{index}/{document}/{identifier}',
            '/{index}/{document}/{identifier}/_source'
        ],
        'HEAD': [
            '/{index}/{document}/{identifier}',
            '/{index}/{document}/{identifier}/_source'
        ]
    }

    def inspect(self, client):
        source_filter = client.create_source_filter('api/documents/get', self.index, self.document,
                                                    SourceFilter.from_query(self.query))
        if source_filter is None:
            raise PermissionError('You are not permitted to access the requested document and/or fields.')
        elif source_filter:
            self.query.discard('_source', '_source_include', '_source_exclude')
            self.query.update(source_filter.as_query())

        if self.query.get('fields'):
            forbidden_fields = []
            for field in (field.strip() for v in self.query['fields'] for field in v.split(',')):
                if field and not client.can('api/documents/get', self.index, self.document, field):
                    forbidden_fields.append(field)

            if forbidden_fields:
                # The fields parameter is not rewritten since it does not support
                # wildcards and therefore contains only explicit values
                raise PermissionError('You are not permitted to access the following fields: {0}'
                                      ''.format(', '.join(forbidden_fields)))


class DeleteApiRequest(ElasticRequest):
    locations = {
        'DELETE': '/{index}/{document}/{identifier}'
    }

    def inspect(self, client):
        # TODO: Check if it's required to validate a parent's id (Whether the client has access to the parent's type)
        if not client.can('api/documents/delete', self.index, self.document):
            raise PermissionError('You are not permitted to delete documents of this type in the given index.')
        elif client.has_restriction(self.index, self.document):
            raise PermissionError('You are restricted to specific fields of the given type.')
        elif not self.query.is_false('refresh') and not client.can('api/indices/refresh', self.index):
            raise PermissionError('You are not permitted to refresh this index.')


class UpdateApiRequest(ElasticRequest):
    locations = {
        'POST': [
            '/{index}/{document}/{identifier}',
            '/{index}/{document}/{identifier}/_update'
        ]
    }

    def inspect(self, client):
        if not self.query.is_false('refresh') and not client.can('api/indices/refresh', self.index):
            raise PermissionError('You are not permitted to refresh this index.')
        elif 'script' in self.json:
            if not client.can('api/documents/update', self.index, self.document):
                raise PermissionError('You are not permitted to update this document.')
            elif not client.can('api/feature/script', self.index, self.document):
                raise PermissionError('You are not permitted to perform scripted updates of this document.')
        elif self.json.get('doc'):
            self._inspect_document(client, self.index, self.document, self.json['doc'])
            if self.json.get('upsert'):
                self._inspect_document(client, self.index, self.document, self.json['upsert'])
        elif not client.can('api/documents/update', self.index, self.document):
            raise PermissionError('You are not permitted to update this document.')

        if self.query.get('fields'):
            forbidden_fields = []
            for field in (field.strip() for v in self.query['fields'] for field in v.split(',')):
                if field == '_source' and client.has_restriction(self.index, self.document):
                    raise PermissionError('"_source" is not available. You are restricted to specific fields.')
                elif field and not client.can('api/documents/get', self.index, self.document, field):
                    forbidden_fields.append(field)

            if forbidden_fields:
                raise PermissionError('You are not permitted to access the following fields: {0}'
                                      ''.format(', '.join(forbidden_fields)))

    def _inspect_document(self, client, index, document_type, document):
        forbidden = []
        for key, value in document.iteritems():
            if isinstance(value, dict):
                fields = self._aggregate_fields(value, key)
            else:
                fields = [key]

            for field in fields:
                if not client.can('api/documents/update', index, document_type, field):
                    forbidden.append(field)

        if forbidden:
            raise PermissionError('You are not permitted to update the following fields: {0}'
                                  ''.format(', '.join(forbidden)))

    def _aggregate_fields(self, obj, path):
        for key, value in obj.iteritems():
            key_path = '.'.join((path, key))

            try:
                for key_path_extension in self._aggregate_fields(value, key_path):
                    yield key_path_extension
            except AttributeError:
                yield key_path


class MultiGetApiRequest(ElasticRequest):
    _errors = None

    before = 'UpdateApiRequest'
    locations = {
        'GET': [
            '/_mget',
            '/{index}/_mget',
            '/{index}/{document}/_mget'
        ],
        'POST': [
            '/_mget',
            '/{index}/_mget',
            '/{index}/{document}/_mget'
        ]
    }

    @Permission('api/bulk')
    def inspect(self, client):
        # TODO: Error handling for unexpected types
        default_index = self.get_match('index')
        default_document_type = self.get_match('document')
        default_source_filter = SourceFilter.from_query(self.query)
        default_fields = [field.strip() for v in self.query.get('fields', []) for field in v.split(',')]

        docs = self.json.get('docs', [])
        if 'ids' in self.json:
            prepend = next(self.json.iterkeys()) == 'ids'
            for i, document_id in enumerate(self.json.pop('ids')):
                if prepend:
                    docs.insert(i, {'_id': document_id})
                else:
                    docs.append({'_id': document_id})

        documents, self._errors = [], []
        for i, document in enumerate(docs):
            index = document.get('_index', default_index)
            if not index:
                raise RequestError(400, 'Document #{0} is missing an index.'.format(i))

            error = None
            if not client.can('api/documents/get', index):
                error = 'You are not permitted to access documents in index "{0}".'.format(index)
            elif not client.has_restriction(index):
                documents.append(document)
                continue

            document_type = document.get('_type', default_document_type)
            if not error and (document_type is None or document_type.strip() == '_all'):
                try:
                    type_filter = client.create_filter_string('api/documents/get', index=index, single=True)
                except MultipleIncludesError as error:
                    error = 'You are restricted to specific types. Please pick a single type' \
                            ' from the following list: {0}'.format(', '.join(error.includes))
                else:
                    document_type = str(next(type_filter.iter_patterns()))
                    if '*' in document_type or ',' in document_type:
                        error = 'You are restricted to specific types. Please specify a type.'

            if not error and document.get('fields', default_fields):
                forbidden_fields = [field for field in document.get('fields', default_fields)
                                    if not client.can('api/documents/get', index, document_type, field)]
                if forbidden_fields:
                    error = 'You are not permitted to access the following fields: {0}' \
                            ''.format(', '.join(forbidden_fields))

            if not error:
                requested_source = SourceFilter.from_json(document.get('_source'))
                source_filter = client.create_source_filter('api/documents/get', index, document_type,
                                                            requested_source or default_source_filter)
                if source_filter is None:
                    error = 'You are not permitted to access this document or the requested fields.'
                elif source_filter:
                    document['_source'] = source_filter.as_json()

            if not error:
                documents.append(document)
            else:
                self._errors.append((i, {
                    '_index': index,
                    '_type': document_type,
                    '_id': document.get('_id'),
                    'error': '[{0}] {1}'.format(APP_NAME, error)
                }))

        if not documents and self._errors:
            response = ElasticResponse()
            response.content = self.json_encode({'docs': [d for p, d in self._errors]},
                                                not self.query.is_false('pretty'))
            response.headers['Content-Length'] = str(len(response.content))
            response.headers['Content-Type'] = 'application/json'
            response.status_code = 200
            del self._errors
            return response

        self.json['docs'] = documents
        self.body = self.json_encode(self.json)
        self.query.discard('_source', '_source_include', '_source_exclude')

    def transform(self, stream, chunk_size):
        if not self._errors:
            for chunk in stream:
                yield chunk
            return

        payload = ''.join(stream)

        try:
            data = self.json_decode(payload)
        except ValueError:
            pass
        else:
            for position, document in self._errors:
                data['docs'].insert(position, document)

            payload = self.json_encode(data, not self.query.is_false('pretty'))
            if 'Content-Length' in self.context.response.headers:
                self.context.response.headers['Content-Length'] = str(len(payload))

        while payload:
            yield payload[:chunk_size]
            payload = payload[chunk_size:]


class BulkApiRequest(ElasticRequest):
    locations = {
        'POST': [
            '/_bulk',
            '/{index}/_bulk',
            '/{index}/{document}/_bulk'
        ]
    }

    @Permission('api/bulk')
    def inspect(self, client):
        pass


class DeleteByQueryApiRequest(ElasticRequest):
    locations = {
        'DELETE': [
            '/_query',
            '/{indices}/_query',
            '/{indices}/{documents}/_query'
        ]
    }

    @Permissions('api/feature/deprecated', 'api/documents/deleteByQuery')
    def inspect(self, client):
        pass


class TermVectorApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/{index}/{document}/_termvector',
            '/{index}/{document}/{identifier}/_termvector'
        ]
    }

    @Permission('api/documents/termVector')
    def inspect(self, client):
        pass


class MultiTermVectorApiRequest(ElasticRequest):
    locations = {
        'GET': [
            '/_mtermvectors',
            '/{index}/_mtermvectors',
            '/{index}/{document}/_mtermvectors'
        ]
    }

    @Permissions('api/bulk', 'api/documents/termVector')
    def inspect(self, client):
        pass
