# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

from elasticarmor import APP_NAME
from elasticarmor.auth import MultipleIncludesError
from elasticarmor.request import *
from elasticarmor.util.elastic import SourceFilter, FieldsFilter


class IndexApiRequest(ElasticRequest):
    locations = {
        'POST': [
            '/{index}/{document}',
            '/{index}/{document}/{identifier}',
            '/{index}/{document}/{identifier}/_create'
        ],
        'PUT': [
            '/{index}/{document}/{identifier}',
            '/{index}/{document}/{identifier}/_create'
        ]
    }

    @property
    def _op_type(self):
        if self.path.endswith('/_create'):
            return 'create'

        return self.query.last('op_type')

    @Permission('api/documents/index')
    def inspect(self, client):
        # TODO: Check if it's required to validate a parent's id (Whether the client has access to the parent's type)
        if not self.get_match('identifier') and not self._op_type == 'create':
            if client.has_restriction(self.index, self.document):
                raise PermissionError('You are restricted to specific fields of the given type. Please use'
                                      ' either the update api instead or the "create" operation-type.')

        if not self.query.is_false('refresh') and not client.can('api/indices/refresh', self.index):
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

    @Permission('api/documents/get')
    def inspect(self, client):
        fields_filter = None
        if not self.path.endswith('/_source'):
            fields_filter = client.create_fields_filter('api/documents/get', self.index, self.document,
                                                        FieldsFilter.from_query(self.query))
            if fields_filter is None:
                raise PermissionError(
                    'You are not permitted to access this document or any of the requested stored fields.')
            elif fields_filter:
                self.query.update(fields_filter.as_query())

        if not fields_filter or fields_filter.requires_source:
            source_filter = client.create_source_filter('api/documents/get', self.index, self.document,
                                                        SourceFilter.from_query(self.query))
            if source_filter is None:
                raise PermissionError('You are not permitted to access any of the requested source fields.')
            elif source_filter:
                self.query.discard('_source', '_source_include', '_source_exclude')
                self.query.update(source_filter.as_query())


class DeleteApiRequest(ElasticRequest):
    locations = {
        'DELETE': '/{index}/{document}/{identifier}'
    }

    @Permission('api/documents/delete')
    def inspect(self, client):
        # TODO: Check if it's required to validate a parent's id (Whether the client has access to the parent's type)
        if client.has_restriction(self.index, self.document):
            raise PermissionError('You are restricted to specific fields of the given type.')
        elif not self.query.is_false('refresh') and not client.can('api/indices/refresh', self.index):
            raise PermissionError('You are not permitted to refresh this index.')


class UpdateApiRequest(ElasticRequest):
    locations = {
        'POST': '/{index}/{document}/{identifier}/_update'
    }

    @Permission('api/documents/update')
    def inspect(self, client):
        if not self.query.is_false('refresh') and not client.can('api/indices/refresh', self.index):
            raise PermissionError('You are not permitted to refresh this index.')
        elif 'script' in self.json and not client.can('api/feature/script', self.index, self.document):
            raise PermissionError('You are not permitted to perform scripted updates of this document.')
        elif self.json.get('doc'):
            self._inspect_document(client, self.index, self.document, self.json['doc'])
            if self.json.get('upsert'):
                self._inspect_document(client, self.index, self.document, self.json['upsert'])

        fields_filter = client.create_fields_filter('api/documents/get', self.index, self.document,
                                                    FieldsFilter.from_query(self.query))
        if fields_filter is None:
            raise PermissionError('You are not permitted to access any of the requested stored fields.')
        elif fields_filter:
            if fields_filter.requires_source and client.has_restriction(self.index, self.document):
                raise PermissionError('"_source" is not available. You are restricted to specific fields.')

            self.query.update(fields_filter.as_query())

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

    before = [
        'GetIndexApiRequest',
        'IndexApiRequest',
        'GetApiRequest'
    ]

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

    @Permission('api/bulk', scope='cluster')
    def inspect(self, client):
        # TODO: Error handling for unexpected types
        default_index = self.get_match('index')
        default_document_type = self.get_match('document')
        default_source_filter = SourceFilter.from_query(self.query)
        default_fields_filter = FieldsFilter.from_query(self.query)

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
            elif isinstance(index, list):
                index = index[-1]
                document['_index'] = index

            error = None
            if not client.can('api/documents/get', index):
                error = 'You are not permitted to access documents in index "{0}".'.format(index)
            elif not client.has_restriction(index):
                documents.append(document)
                continue

            document_type = document.get('_type', default_document_type)
            if isinstance(document_type, list):
                document_type = document_type[-1]
                document['_type'] = document_type

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

            inspect_source = True
            if not error and ('fields' in document or default_fields_filter):
                fields_filter = client.create_fields_filter(
                    'api/documents/get', index, document_type,
                    FieldsFilter.from_json(document['fields']) if 'fields' in document else default_fields_filter)
                if fields_filter is None:
                    error = 'You are not permitted to access this document or any of the requested stored fields.'
                elif fields_filter:
                    document['fields'] = fields_filter.as_json()
                    inspect_source = fields_filter.requires_source

            if not error and inspect_source:
                requested_source = SourceFilter.from_json(document.get('_source'))
                source_filter = client.create_source_filter('api/documents/get', index, document_type,
                                                            requested_source or default_source_filter)
                if source_filter is None:
                    error = 'You are not permitted to access any of the requested source fields.'
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
    before = 'IndexApiRequest'
    locations = {
        'POST': [
            '/_bulk',
            '/{index}/_bulk',
            '/{index}/{document}/_bulk'
        ]
    }

    @Permission('api/feature/notImplemented')
    @Permission('api/bulk', scope='cluster')
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

    @Permission('api/feature/deprecated', scope='cluster')
    @Permission('api/documents/deleteByQuery')
    def inspect(self, client):
        pass


class TermVectorApiRequest(ElasticRequest):
    before = 'GetApiRequest'
    locations = {
        'GET': [
            '/{index}/{document}/_termvector{s}',
            '/{index}/{document}/{identifier}/_termvector{s}'
        ]
    }

    @Permission('api/documents/termVector')
    def inspect(self, client):
        pass


class MultiTermVectorApiRequest(ElasticRequest):
    before = [
        'GetIndexApiRequest',
        'GetApiRequest'
    ]

    locations = {
        'GET': [
            '/_mtermvectors',
            '/{index}/_mtermvectors',
            '/{index}/{document}/_mtermvectors'
        ]
    }

    @Permission('api/bulk', scope='cluster')
    @Permission('api/documents/termVector')
    def inspect(self, client):
        pass
