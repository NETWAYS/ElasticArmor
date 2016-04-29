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
     * Create and return the tabs for the detail actions
     *
     * @param   string  $roleName
     *
     * @return  Tabs
     */
    protected function createDetailTabs($roleName)
    {
        $tabs = $this->getTabs();

        $tabs->add(
            'restrictions',
            array(
                'url'       => 'elasticarmor/roles/restrictions',
                'urlParams' => array('role' => $roleName),
                'label'     => $this->translate('Restrictions'),
                'title'     => $this->translate('Set up restrictions for specific indices, types and fields')
            )
        );
        $tabs->add(
            'permissions',
            array(
                'url'       => 'elasticarmor/roles/permissions',
                'urlParams' => array('role' => $roleName),
                'label'     => $this->translate('Permissions'),
                'title'     => $this->translate('Define what to permit on a cluster-wide basis')
            )
        );
        $tabs->add(
            'users',
            array(
                'url'       => 'elasticarmor/roles/users',
                'urlParams' => array('role' => $roleName),
                'label'     => $this->translate('Users'),
                'title'     => $this->translate('Assign this role to one or more users')
            )
        );
        $tabs->add(
            'groups',
            array(
                'url'       => 'elasticarmor/roles/groups',
                'urlParams' => array('role' => $roleName),
                'label'     => $this->translate('Groups'),
                'title'     => $this->translate('Assign this role to one or more groups')
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

    /**
     * Remove a role
     */
    public function removeAction()
    {
        $roleName = $this->params->getRequired('role');

        $form = new RoleForm();
        $form->setRedirectUrl('elasticarmor/roles/list');
        $form->setRepository($this->getConfigurationBackend());

        try {
            $form->remove($roleName)->handleRequest();
        } catch (NotFoundError $_) {
            $this->httpNotFound(sprintf($this->translate('Role "%s" not found'), $roleName));
        }

        $this->getTabs()->add('roles/remove', array(
            'active'    => true,
            'label'     => $this->translate('Remove Role'),
            'url'       => Url::fromRequest()
        ));

        $this->view->form = $form;
        $this->render('form');
    }

    /**
     * List all configured restrictions for a role
     */
    public function restrictionsAction()
    {
        $roleName = $this->params->getRequired('role');

        $role = $this->getConfigurationBackend()->fetchDocument('role', $roleName, array('name', 'privileges'));
        if ($role === false) {
            $this->httpNotFound(sprintf($this->translate('Role "%s" not found'), $roleName));
        }

        $this->view->role = $role;
        $this->createDetailTabs($roleName)->activate('restrictions');
    }

    /**
     * List all configured cluster permissions for a role
     */
    public function permissionsAction()
    {
        $roleName = $this->params->getRequired('role');

        $role = $this->getConfigurationBackend()->fetchDocument('role', $roleName, array('name', 'privileges'));
        if ($role === false) {
            $this->httpNotFound(sprintf($this->translate('Role "%s" not found'), $roleName));
        }

        $this->view->role = $role;
        $this->createDetailTabs($roleName)->activate('permissions');
    }

    /**
     * List all users assigned to a role
     */
    public function usersAction()
    {
        $roleName = $this->params->getRequired('role');

        $role = $this->getConfigurationBackend()->fetchDocument('role', $roleName, array('name', 'users'));
        if ($role === false) {
            $this->httpNotFound(sprintf($this->translate('Role "%s" not found'), $roleName));
        }

        $this->view->role = $role;
        $this->createDetailTabs($roleName)->activate('users');
    }

    /**
     * List all groups assigned to a role
     */
    public function groupsAction()
    {
        $roleName = $this->params->getRequired('role');

        $role = $this->getConfigurationBackend()->fetchDocument('role', $roleName, array('name', 'groups'));
        if ($role === false) {
            $this->httpNotFound(sprintf($this->translate('Role "%s" not found'), $roleName));
        }

        $this->view->role = $role;
        $this->createDetailTabs($roleName)->activate('groups');
    }
}
