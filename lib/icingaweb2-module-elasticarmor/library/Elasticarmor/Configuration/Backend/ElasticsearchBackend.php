<?php
/* ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+ */

namespace Icinga\Module\Elasticarmor\Configuration\Backend;

use Icinga\Application\Config;
use Icinga\Data\Filter\Filter;
use Icinga\Data\Filter\FilterExpression;
use Icinga\Repository\RepositoryQuery;
use Icinga\Module\Elasticsearch\Repository\ElasticsearchRepository;
use Icinga\Module\Elasticsearch\RestApi\RestApiClient;

class ElasticsearchBackend extends ElasticsearchRepository
{
    /**
     * {@inheritdoc}
     */
    protected $queryColumns = array(
        'role' => array(
            'name'          => '_id',
            'privileges'
        ),
        'role_user' => array(
            'role'      => '_parent',
            'id'        => '_id',
            'user'      => 'name',
            'backend'
        ),
        'role_group' => array(
            'role'      => '_parent',
            'id'        => '_id',
            'group'     => 'name',
            'backend'
        )
    );

    /**
     * {@inheritdoc}
     */
    protected $blacklistedQueryColumns = array(
        'role'
    );

    /**
     * {@inheritdoc}
     */
    protected $filterColumns = array(
        'name'
    );

    /**
     * {@inheritdoc}
     */
    protected $searchColumns = array(
        'name'
    );

    /**
     * {@inheritdoc}
     */
    protected $sortRules = array(
        'name' => array(
            'order' => 'asc'
        ),
        'user' => array(
            'order' => 'asc'
        ),
        'group' => array(
            'order' => 'asc'
        )
    );

    /**
     * {@inheritdoc}
     */
    public function insert($documentType, array $document, $refresh = true)
    {
        if (is_string($documentType)) {
            $documentType = explode('/', $documentType);
        }

        if (isset($document['name'])) {
            $documentType[] = $document['name'];
            unset($document['name']);
        }

        return parent::insert($documentType, $document, $refresh);
    }

    /**
     * {@inheritdoc}
     */
    public function update($documentType, array $document, Filter $filter = null, $refresh = true, $fetchSource = false)
    {
        $newDocumentId = null;
        if (isset($document['name'])) {
            $newDocumentId = $document['name'];
            unset($document['name']);
        }

        $updatedDocument = parent::update(
            $documentType,
            $document,
            $filter,
            $refresh,
            $newDocumentId !== null || $fetchSource
        );
        if ($newDocumentId === null || $newDocumentId === $updatedDocument['_id']) {
            return $updatedDocument;
        }

        $this->insert(array($documentType, $newDocumentId), $updatedDocument['get']['_source'], $refresh);
        $this->delete(array($documentType, $updatedDocument['_id']), null, $refresh);
        $updatedDocument['_id'] = $newDocumentId;
        return $updatedDocument;
    }

    /**
     * {@inheritdoc}
     */
    public function requireFilterColumn($table, $name, RepositoryQuery $query = null, FilterExpression $filter = null)
    {
        $name = parent::requireFilterColumn($table, $name, $query, $filter);
        if ($name === '_id') {
            $name = '_uid';

            if ($filter !== null) {
                $filter->setExpression(sprintf('%s#%s', $table, $filter->getExpression()));
            }
        }

        return $name;
    }

    /**
     * Create and return a new instance of ElasticsearchBackend
     *
     * @param   ConfigObject    $config     The configuration to use, otherwise the module's configuration
     *
     * @return  ElasticsearchBackend
     */
    public static function fromConfig(ConfigObject $config = null)
    {
        if ($config === null) {
            $config = Config::module('elasticarmor')->getSection('elasticarmor');
        }

        $resource = new RestApiClient(
            $config->get('url', 'localhost:59200'),
            $config->get('username'),
            $config->get('password'),
            $config->get('certificate_path')
        );

        $backend = new static($resource);
        $backend->setName('elasticarmor_config_backend');
        $backend->setIndex($config->get('index', '.elasticarmor'));
        return $backend;
    }
}
