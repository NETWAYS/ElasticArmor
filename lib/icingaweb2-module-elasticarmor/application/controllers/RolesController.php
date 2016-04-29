<?php
/* ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+ */

namespace Icinga\Module\Elasticarmor\Controllers;

use Icinga\Web\Controller;
use Icinga\Web\Widget\Tabs;
use Icinga\Module\Elasticarmor\Configuration\Backend\ElasticsearchBackend;

class RolesController extends Controller
{
    /**
     * Create and return the tabs for the list action
     *
     * @return  Tabs
     */
    protected function createListTabs()
    {
        $tabs = $this->getTabs();

        $tabs->add(
            'roles/list',
            array(
                'baseTarget'    => '_main',
                'label'         => $this->translate('Roles'),
                'title'         => $this->translate(
                    'Configure roles to permit or restrict users and groups accessing Elasticsearch'
                ),
                'url'           => 'elasticarmor/roles/list'
            )
        );

        return $tabs;
    }

    /**
     * Return the configuration backend to use
     */
    protected function getConfigurationBackend()
    {
        return ElasticsearchBackend::fromConfig();
    }

    /**
     * Redirect to the list action
     */
    public function indexAction()
    {
        $this->redirectNow('elasticarmor/roles/list');
    }

    /**
     * List all configured roles
     */
    public function listAction()
    {
        $query = ElasticsearchBackend::fromConfig()->select(array('name'));

        $this->view->roles = $query;
        $this->createListTabs()->activate('roles/list');

        $this->setupPaginationControl($query);
        $this->setupFilterControl($query);
        $this->setupLimitControl();
        $this->setupSortControl(
            array(
                'name' => $this->translate('Name'),
            ),
            $query
        );
    }
}
