<?php
/* ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+ */

namespace Icinga\Module\Elasticarmor\Controllers;

use Exception;
use Icinga\Application\Logger;
use Icinga\Exception\NotFoundError;
use Icinga\Data\Filter\Filter;
use Icinga\Web\Controller\AuthBackendController;
use Icinga\Web\Form;
use Icinga\Web\Notification;
use Icinga\Web\Url;
use Icinga\Web\Widget\Tabs;
use Icinga\Module\Elasticarmor\Configuration\Backend\ElasticsearchBackend;
use Icinga\Module\Elasticarmor\Forms\Configuration\PermissionsForm;
use Icinga\Module\Elasticarmor\Forms\Configuration\RestrictionForm;
use Icinga\Module\Elasticarmor\Forms\Configuration\RoleForm;
use Icinga\Module\Elasticarmor\Web\Role\RestrictionsRenderer;

class RolesController extends AuthBackendController
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
     * Fetch and return all users from all user backends
     *
     * @return  array
     */
    protected function fetchUsers()
    {
        $addedUsers = $this->getConfigurationBackend()
            ->select()
            ->from('role_user', array('user'))
            ->where('role', $this->params->getRequired('role'))
            ->limit(1000) // Elasticsearch's default limit is 10, there is no efficient way to express "unlimited"
            ->fetchColumn();
        $filter = Filter::matchAll();
        if (! empty($addedUsers)) {
            $filter = Filter::expression('user_name', '!=', $addedUsers);
        }

        $users = array();
        foreach ($this->loadUserBackends('Icinga\Data\Selectable') as $backend) {
            try {
                foreach ($backend->select(array('user_name'))->addFilter($filter) as $row) {
                    $row->backend_name = $backend->getName();
                    $users[] = $row;
                }
            } catch (Exception $e) {
                Logger::error($e);
                Notification::warning(sprintf(
                    $this->translate('Failed to fetch any users from backend %s. Please check your log'),
                    $backend->getName()
                ));
            }
        }

        return $users;
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
        $this->view->restrictions = new RestrictionsRenderer($role->name, $role->privileges ?: array());
        $this->createDetailTabs($roleName)->activate('restrictions');
    }

    /**
     * Create a new restriction
     */
    public function restrictionsCreateAction()
    {
        $roleName = $this->params->getRequired('role');
        $restrictionPath = $this->params->getRequired('path');

        $role = $this->getConfigurationBackend()->fetchDocument('role', $roleName, array('privileges'));
        if ($role === false) {
            $this->httpNotFound(sprintf($this->translate('Role "%s" not found'), $roleName));
        }

        $form = new RestrictionForm();
        $form->setRedirectUrl(Url::fromPath('elasticarmor/roles/restrictions', array('role' => $roleName)));
        $form->setRepository($this->getConfigurationBackend());
        $form->edit($roleName, $role->privileges ?: array());
        $form->createRestriction($restrictionPath);
        $form->handleRequest();

        $this->getTabs()->add('roles/restrictions/create', array(
            'active'    => true,
            'label'     => $this->translate('Create Restriction'),
            'url'       => Url::fromRequest()
        ));

        $this->view->form = $form;
        $this->render('form');
    }

    /**
     * Update a restriction
     */
    public function restrictionsUpdateAction()
    {
        $roleName = $this->params->getRequired('role');
        $restrictionPath = $this->params->getRequired('path');

        $role = $this->getConfigurationBackend()->fetchDocument('role', $roleName, array('privileges'));
        if ($role === false) {
            $this->httpNotFound(sprintf($this->translate('Role "%s" not found'), $roleName));
        }

        $form = new RestrictionForm();
        $form->setRedirectUrl(Url::fromPath('elasticarmor/roles/restrictions', array('role' => $roleName)));
        $form->setRepository($this->getConfigurationBackend());
        $form->edit($roleName, $role->privileges ?: array());
        $form->updateRestriction($restrictionPath);
        $form->handleRequest();

        $this->getTabs()->add('roles/restrictions/update', array(
            'active'    => true,
            'label'     => $this->translate('Update Restriction'),
            'url'       => Url::fromRequest()
        ));

        $this->view->form = $form;
        $this->render('form');
    }

    /**
     * Remove a restriction
     */
    public function restrictionsRemoveAction()
    {
        $roleName = $this->params->getRequired('role');
        $restrictionPath = $this->params->getRequired('path');

        $role = $this->getConfigurationBackend()->fetchDocument('role', $roleName, array('privileges'));
        if ($role === false) {
            $this->httpNotFound(sprintf($this->translate('Role "%s" not found'), $roleName));
        }

        $form = new RestrictionForm();
        $form->setRedirectUrl(Url::fromPath('elasticarmor/roles/restrictions', array('role' => $roleName)));
        $form->setRepository($this->getConfigurationBackend());
        $form->edit($roleName, $role->privileges ?: array());
        $form->removeRestriction($restrictionPath);
        $form->handleRequest();

        $this->getTabs()->add('roles/restrictions/remove', array(
            'active'    => true,
            'label'     => $this->translate('Remove Restriction'),
            'url'       => Url::fromRequest()
        ));

        $this->view->form = $form;
        $this->render('form');
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

        $form = new PermissionsForm();
        $form->setRepository($this->getConfigurationBackend());
        $form->edit($roleName, $role->privileges ?: array())->handleRequest();

        $this->view->role = $role;
        $this->view->form = $form;
        $this->createDetailTabs($roleName)->activate('permissions');
    }

    /**
     * List all users assigned to a role
     */
    public function usersAction()
    {
        $roleName = $this->params->getRequired('role');
        $backend = $this->getConfigurationBackend();

        $role = $backend->fetchDocument('role', $roleName, array('name'));
        if ($role === false) {
            $this->httpNotFound(sprintf($this->translate('Role "%s" not found'), $roleName));
        }

        $members = $backend
            ->select()
            ->from('role_user', array('id', 'user', 'backend'))
            ->where('role', $roleName);

        $this->setupFilterControl(
            $members,
            array('user', 'backend'),
            array('user'),
            array('role')
        );
        $this->setupPaginationControl($members);
        $this->setupLimitControl();
        $this->setupSortControl(
            array(
                'user'      => $this->translate('Username'),
                'backend'   => $this->translate('Backend')
            ),
            $members
        );

        $this->view->role = $role;
        $this->view->members = $members;
        $this->createDetailTabs($roleName)->activate('users');

        $removeForm = new Form();
        $removeForm->setUidDisabled();
        $removeForm->setAction(
            Url::fromPath('elasticarmor/roles/users-remove', array('role' => $roleName))
        );
        $removeForm->addElement('hidden', 'user_id', array(
            'isArray'       => true,
            'decorators'    => array('ViewHelper')
        ));
        $removeForm->addElement('hidden', 'redirect', array(
            'value'         => Url::fromPath('elasticarmor/roles/users', array('role' => $roleName)),
            'decorators'    => array('ViewHelper')
        ));
        $removeForm->addElement('button', 'btn_submit', array(
            'escape'        => false,
            'type'          => 'submit',
            'class'         => 'link-button spinner',
            'value'         => 'btn_submit',
            'decorators'    => array('ViewHelper'),
            'label'         => $this->view->icon('cancel'),
            'title'         => $this->translate('Remove this member')
        ));
        $this->view->removeForm = $removeForm;
    }

    /**
     * List all groups assigned to a role
     */
    public function groupsAction()
    {
        $roleName = $this->params->getRequired('role');
        $backend = $this->getConfigurationBackend();

        $role = $backend->fetchDocument('role', $roleName, array('name'));
        if ($role === false) {
            $this->httpNotFound(sprintf($this->translate('Role "%s" not found'), $roleName));
        }

        $members = $backend
            ->select()
            ->from('role_group', array('id', 'group', 'backend'))
            ->where('role', $roleName);

        $this->setupFilterControl(
            $members,
            array('group', 'backend'),
            array('group'),
            array('role')
        );
        $this->setupPaginationControl($members);
        $this->setupLimitControl();
        $this->setupSortControl(
            array(
                'group'     => $this->translate('Group'),
                'backend'   => $this->translate('Backend')
            ),
            $members
        );

        $this->view->role = $role;
        $this->view->members = $members;
        $this->createDetailTabs($roleName)->activate('groups');

        $removeForm = new Form();
        $removeForm->setUidDisabled();
        $removeForm->setAction(
            Url::fromPath('roles/groups-remove', array('role' => $roleName))
        );
        $removeForm->addElement('hidden', 'group_id', array(
            'isArray'       => true,
            'decorators'    => array('ViewHelper')
        ));
        $removeForm->addElement('hidden', 'redirect', array(
            'value'         => Url::fromPath('elasticarmor/roles/groups', array('role' => $roleName)),
            'decorators'    => array('ViewHelper')
        ));
        $removeForm->addElement('button', 'btn_submit', array(
            'escape'        => false,
            'type'          => 'submit',
            'class'         => 'link-button spinner',
            'value'         => 'btn_submit',
            'decorators'    => array('ViewHelper'),
            'label'         => $this->view->icon('cancel'),
            'title'         => $this->translate('Remove this member')
        ));
        $this->view->removeForm = $removeForm;
    }
}
