<?php
/* ElasticArmor' => '(c) 2016 NETWAYS GmbH' => 'GPLv2+ */

namespace Icinga\Module\Elasticarmor\Forms\Configuration;

use Icinga\Data\Filter\Filter;
use Icinga\Forms\RepositoryForm;
use Icinga\Web\Url;

class RoleForm extends RepositoryForm
{
    /**
     * Cluster context identifier
     */
    const CLUSTER_CONTEXT = 'cluster';

    /**
     * Index context identifier
     */
    const INDEX_CONTEXT = 'indices';

    /**
     * Document type context identifier
     */
    const TYPE_CONTEXT = 'types';

    /**
     * Field context identifier
     */
    const FIELD_CONTEXT = 'fields';

    /**
     * All available permissions and their smallest scope
     *
     * @var array
     */
    protected $availablePermissions = array(
        '*'                             => 'cluster',
        'config/*'                      => 'cluster',
        'config/authorization'          => 'cluster',
        'api/*'                         => 'cluster',
        'api/cluster/*'                 => 'cluster',
        'api/cluster/health'            => 'indices',
        'api/cluster/state'             => 'cluster',
        'api/cluster/stats'             => 'cluster',
        'api/cluster/pendingTasks'      => 'cluster',
        'api/cluster/reroute'           => 'cluster',
        'api/cluster/get/settings'      => 'cluster',
        'api/cluster/update/settings'   => 'cluster',
        'api/cluster/nodes/*'           => 'cluster',
        'api/cluster/nodes/stats'       => 'cluster',
        'api/cluster/nodes/info'        => 'cluster',
        'api/cluster/nodes/hotThreads'  => 'cluster',
        'api/cluster/nodes/shutdown'    => 'cluster',
        'api/indices/*'                 => 'indices',
        'api/indices/get/*'             => 'types',
        'api/indices/create/*'          => 'types',
        'api/indices/update/*'          => 'types',
        'api/indices/delete/*'          => 'types',
        'api/indices/create/index'      => 'indices',
        'api/indices/delete/index'      => 'indices',
        'api/indices/open'              => 'indices',
        'api/indices/close'             => 'indices',
        'api/indices/create/mappings'   => 'types',
        'api/indices/delete/mappings'   => 'types',
        'api/indices/get/mappings'      => 'types',
        'api/indices/create/aliases'    => 'indices',
        'api/indices/delete/aliases'    => 'indices',
        'api/indices/get/aliases'       => 'indices',
        'api/indices/update/settings'   => 'indices',
        'api/indices/get/settings'      => 'indices',
        'api/indices/analyze'           => 'indices',
        'api/indices/create/templates'  => 'cluster',
        'api/indices/delete/templates'  => 'cluster',
        'api/indices/get/templates'     => 'cluster',
        'api/indices/create/warmers'    => 'indices',
        'api/indices/delete/warmers'    => 'indices',
        'api/indices/get/warmers'       => 'indices',
        'api/indices/stats'             => 'indices',
        'api/indices/segments'          => 'indices',
        'api/indices/recovery'          => 'indices',
        'api/indices/cache/clear'       => 'indices',
        'api/indices/flush'             => 'indices',
        'api/indices/refresh'           => 'indices',
        'api/indices/optimize'          => 'indices',
        'api/indices/upgrade'           => 'indices',
        'api/documents/*'               => 'fields',
        'api/documents/index'           => 'types',
        'api/documents/get'             => 'fields',
        'api/documents/delete'          => 'types',
        'api/documents/update'          => 'fields',
        'api/documents/deleteByQuery'   => 'types',
        'api/documents/termVector'      => 'types',
        'api/search/*'                  => 'fields',
        'api/search/documents'          => 'fields',
        'api/search/templates'          => 'cluster',
        'api/search/shards'             => 'indices',
        'api/search/suggest'            => 'cluster',
        'api/search/explain'            => 'fields',
        'api/search/percolate'          => 'types',
        'api/search/fieldStats'         => 'indices',
        'api/cat'                       => 'cluster',
        'api/bulk'                      => 'cluster',
        'api/feature/deprecated'        => 'cluster',
        'api/feature/facets'            => 'types',
        'api/feature/fuzzyLikeThis'     => 'fields',
        'api/feature/innerHits'         => 'types',
        'api/feature/moreLikeThis'      => 'fields',
        'api/feature/notImplemented'    => 'types',
        'api/feature/queryString'       => 'types',
        'api/feature/script'            => 'fields'
    );

    /**
     * {@inheritdoc}
     */
    protected function onInsertSuccess()
    {
        $this->setRedirectUrl(Url::fromPath(
            'elasticarmor/roles/restrictions',
            array('role' => $this->getValue('name'))
        ));
        return parent::onInsertSuccess();
    }

    /**
     * {@inheritdoc}
     */
    protected function onUpdateSuccess()
    {
        $action = $this->getRequest()->getParam('detail');
        if ($action !== null) {
            $this->setRedirectUrl(Url::fromPath(
                sprintf('elasticarmor/roles/%s', $this->getView()->escape($action)),
                array('role' => $this->getValue('name'))
            ));
        }

        return parent::onUpdateSuccess();
    }

    /**
     * {@inheritdoc}
     */
    protected function createInsertElements(array $formData)
    {
        $this->addElement(
            'text',
            'name',
            array(
                'required'  => true,
                'label'     => $this->translate('Name')
            )
        );

        $this->setSubmitLabel($this->translate('Create'));
    }

    /**
     * {@inheritdoc}
     */
    protected function createUpdateElements(array $formData)
    {
        $this->createInsertElements($formData);
        $this->setSubmitLabel($this->translate('Save'));
    }

    /**
     * {@inheritdoc}
     */
    protected function createDeleteElements(array $formData)
    {
        $this->setSubmitLabel(sprintf($this->translate('Remove role %s'), $this->identifier));
    }

    /**
     * {@inheritdoc}
     */
    protected function createFilter()
    {
        return Filter::where('name', $this->identifier);
    }

    /**
     * {@inheritdoc}
     */
    protected function getInsertMessage($success)
    {
        if ($success) {
            $message = $this->translate('Successfully created role %s');
        } else {
            $message = $this->translate('Failed to create role %s');
        }

        return sprintf($message, $this->getValue('name'));
    }

    /**
     * {@inheritdoc}
     */
    protected function getUpdateMessage($success)
    {
        if ($success) {
            $message = $this->translate('Successfully updated role %s');
        } else {
            $message = $this->translate('Failed to update role %s');
        }

        return sprintf($message, $this->identifier);
    }

    /**
     * {@inheritdoc}
     */
    protected function getDeleteMessage($success)
    {
        if ($success) {
            $message = $this->translate('Successfully removed role %s');
        } else {
            $message = $this->translate('Failed to remove role %s');
        }

        return sprintf($message, $this->identifier);
    }

    /**
     * Check whether the given permission is harmful and if so, return a explanation why
     *
     * @param   string|null
     */
    protected function isHarmfulPermission($permission)
    {
        switch ($permission)
        {
            case '*':
            case 'api/*':
                return $this->translate(
                    'This opens up the entire API, including endpoints which'
                    . ' are not fully inspected or not inspected at all.'
                );
            case 'api/cat':
                return $this->translate('No inspection of any kind is being applied yet.');
            case 'api/feature/deprecated':
                return $this->translate(
                    'API endpoints which are deprecated as of Elasticsearch v1.7.x'
                    . ' and have valid alternatives are not being inspected.'
                );
            case 'api/feature/facets':
                return $this->translate(
                    'Faceted searches are not being inspected as they are a relict of Elasticsearch'
                    . ' v0.x and were replaced by aggregations in newer versions.'
                );
            case 'api/feature/fuzzyLikeThis':
                return $this->translate(
                    'While it is possible to regulate the starting point of the Fuzzy Like'
                    . ' This Query, it is not possible to regulate what is being returned.'
                );
            case 'api/feature/innerHits':
                return $this->translate(
                    'The inner hits feature allows to return documents matched in different'
                    . ' scopes. This may allow the user to access non-permitted data.'
                );
            case 'api/feature/moreLikeThis':
                return $this->translate(
                    'While it is possible to regulate the starting point of the More Like This'
                    . ' API/Query, it is not possible to regulate what is being returned.'
                );
            case 'api/indices/create/aliases':
            case 'api/indices/delete/aliases':
            case 'api/indices/create/warmers':
            case 'api/indices/delete/warmers':
            case 'api/indices/stats':
            case 'api/documents/termVector':
            case 'api/search/shards':
            case 'api/search/suggest':
            case 'api/search/explain':
            case 'api/search/percolate':
            case 'api/search/fieldStats':
            case 'api/feature/notImplemented':
                return $this->translate(
                    'API endpoints which are not yet inspected allow the user'
                    . ' to freely perform write operations or access data.'
                );
            case 'api/feature/queryString':
                return $this->translate(
                    'Query string searches are not being inspected yet and'
                    . ' may allow the user to access non-permitted fields.'
                );
            case 'api/feature/script':
                return $this->translate(
                    'Scripts are not being inspected and can possibly access data outside a query\'s scope.'
                );
        }
    }
}
