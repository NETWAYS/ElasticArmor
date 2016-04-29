<?php
/* ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+ */

namespace Icinga\Module\Elasticarmor\Controllers;

use Icinga\Exception\NotFoundError;
use Icinga\Web\Controller;
use Icinga\Web\Url;
use Icinga\Web\Widget\Tabs;
use Icinga\Module\Elasticarmor\Configuration\Backend\ElasticsearchBackend;
use Icinga\Module\Elasticarmor\Forms\Configuration\RoleForm;

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

    /**
     * Create a new role
     */
    public function createAction()
    {
        $form = new RoleForm();
        $form->setRepository($this->getConfigurationBackend());
        $form->add()->handleRequest();

        $this->getTabs()->add('roles/create', array(
            'active'    => true,
            'label'     => $this->translate('Create Role'),
            'url'       => Url::fromRequest()
        ));

        $this->view->form = $form;
        $this->render('form');
    }

    /**
     * Update a role
     */
    public function updateAction()
    {
        $roleName = $this->params->getRequired('role');

        $form = new RoleForm();
        $form->setRepository($this->getConfigurationBackend());

        try {
            $form->edit($roleName)->handleRequest();
        } catch (NotFoundError $_) {
            $this->httpNotFound(sprintf($this->translate('Role "%s" not found'), $roleName));
        }

        $this->getTabs()->add('roles/update', array(
            'active'    => true,
            'label'     => $this->translate('Update Role'),
            'url'       => Url::fromRequest()
        ));

        $this->view->form = $form;
        $this->render('form');
    }
}
