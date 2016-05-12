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
use Icinga\Web\UrlParams;
use Icinga\Web\Widget\Tabs;
use Icinga\Module\Elasticarmor\Configuration\Backend\ElasticsearchBackend;
use Icinga\Module\Elasticarmor\Forms\Configuration\AddRoleGroupForm;
use Icinga\Module\Elasticarmor\Forms\Configuration\AddRoleUserForm;
use Icinga\Module\Elasticarmor\Forms\Configuration\PermissionsForm;
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
                'icon'      => 'eye-off',
                'url'       => 'elasticarmor/roles/restrictions',
                'urlParams' => array('role' => $roleName),
                'label'     => $this->translate('Restrictions'),
                'title'     => $this->translate('Set up restrictions for specific indices, types and fields')
            )
        );
        $tabs->add(
            'permissions',
            array(
                'icon'      => 'lock-open-alt',
                'url'       => 'elasticarmor/roles/permissions',
                'urlParams' => array('role' => $roleName),
                'label'     => $this->translate('Permissions'),
                'title'     => $this->translate('Define what to permit on a cluster-wide basis')
            )
        );
        $tabs->add(
            'users',
            array(
                'icon'      => 'user',
                'url'       => 'elasticarmor/roles/users',
                'urlParams' => array('role' => $roleName),
                'label'     => $this->translate('Users'),
                'title'     => $this->translate('Assign this role to one or more users')
            )
        );
        $tabs->add(
            'groups',
            array(
                'icon'      => 'users',
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
     * Fetch and return all usergroups from all usergroup backends
     *
     * @return  array
     */
    protected function fetchUserGroups()
    {
        $addedGroups = $this->getConfigurationBackend()
            ->select()
            ->from('role_group', array('group'))
            ->where('role', $this->params->getRequired('role'))
            ->limit(1000) // Elasticsearch's default limit is 10, there is no efficient way to express "unlimited"
            ->fetchColumn();
        $filter = Filter::matchAll();
        if (! empty($addedGroups)) {
            $filter = Filter::expression('group_name', '!=', $addedGroups);
        }

        $groups = array();
        foreach ($this->loadUserGroupBackends('Icinga\Data\Selectable') as $backend) {
            try {
                foreach ($backend->select(array('group_name'))->addFilter($filter) as $row) {
                    $row->backend_name = $backend->getName();
                    $groups[] = $row;
                }
            } catch (Exception $e) {
                Logger::error($e);
                Notification::warning(sprintf(
                    $this->translate('Failed to fetch any usergroups from backend %s. Please check your log'),
                    $backend->getName()
                ));
            }
        }

        return $groups;
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
     * Add one or more users to a role
     */
    public function usersAddAction()
    {
        $roleName = $this->params->getRequired('role');
        $backend = $this->getConfigurationBackend();

        $params = new UrlParams();
        $params->set('_source', 'false');
        if ($backend->fetchDocument('role', $roleName, null, $params) === false) {
            $this->httpNotFound(sprintf($this->translate('Role "%s" not found'), $roleName));
        }

        $form = new AddRoleUserForm();
        $form->setBackend($backend);
        $form->setRoleName($roleName);
        $form->setUsers($this->fetchUsers());
        $form->setRedirectUrl(Url::fromPath('elasticarmor/roles/users', array('role' => $roleName)));
        $form->handleRequest();

        $this->getTabs()->add('roles/users/add', array(
            'active'    => true,
            'label'     => $this->translate('Add Users'),
            'url'       => Url::fromRequest()
        ));

        $this->view->form = $form;
        $this->render('form');
    }

    /**
     * Remove one or more users from a role
     */
    public function usersRemoveAction()
    {
        $this->assertHttpMethod('POST');
        $roleName = $this->params->getRequired('role');
        $backend = $this->getConfigurationBackend();

        $form = new Form(array(
            'onSuccess' => function ($form) use ($roleName, $backend) {
                foreach ($form->getValue('user_id') as $userId) {
                    $params = new UrlParams();
                    $params->set('parent', $roleName);

                    if (strpos($userId, '|') !== false) {
                        list($user, $id) = explode('|', $userId, 2);
                    } else {
                        $user = null;
                        $id = $userId;
                    }

                    try {
                        $backend->delete(
                            array('role_user', $id),
                            null,
                            $params
                        );

                        if ($user === null) {
                            Notification::success(mt('elasticarmor', 'User successfully removed'));
                        } else {
                            Notification::success(sprintf(
                                mt('elasticarmor', 'User "%s" has been removed from role "%s"'),
                                $user,
                                $roleName
                            ));
                        }
                    } catch (Exception $e) {
                        Notification::error($e->getMessage());
                    }
                }

                $redirect = $form->getValue('redirect');
                if (! empty($redirect)) {
                    $form->setRedirectUrl(htmlspecialchars_decode($redirect));
                }

                return true;
            }
        ));
        $form->setUidDisabled();
        $form->setSubmitLabel('btn_submit'); // Required to ensure that isSubmitted() is called
        $form->addElement('hidden', 'user_id', array('required' => true, 'isArray' => true));
        $form->addElement('hidden', 'redirect');
        $form->handleRequest();
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
            Url::fromPath('elasticarmor/roles/groups-remove', array('role' => $roleName))
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

    /**
     * Add one or more groups to a role
     */
    public function groupsAddAction()
    {
        $roleName = $this->params->getRequired('role');
        $backend = $this->getConfigurationBackend();

        $params = new UrlParams();
        $params->set('_source', 'false');
        if ($backend->fetchDocument('role', $roleName, null, $params) === false) {
            $this->httpNotFound(sprintf($this->translate('Role "%s" not found'), $roleName));
        }

        $form = new AddRoleGroupForm();
        $form->setBackend($backend);
        $form->setRoleName($roleName);
        $form->setGroups($this->fetchUserGroups());
        $form->setRedirectUrl(Url::fromPath('elasticarmor/roles/groups', array('role' => $roleName)));
        $form->handleRequest();

        $this->getTabs()->add('roles/groups/add', array(
            'active'    => true,
            'label'     => $this->translate('Add Groups'),
            'url'       => Url::fromRequest()
        ));

        $this->view->form = $form;
        $this->render('form');
    }

    /**
     * Remove one or more groups from a role
     */
    public function groupsRemoveAction()
    {
        $this->assertHttpMethod('POST');
        $roleName = $this->params->getRequired('role');
        $backend = $this->getConfigurationBackend();

        $form = new Form(array(
            'onSuccess' => function ($form) use ($roleName, $backend) {
                foreach ($form->getValue('group_id') as $groupId) {
                    $params = new UrlParams();
                    $params->set('parent', $roleName);

                    if (strpos($groupId, '|') !== false) {
                        list($group, $id) = explode('|', $groupId, 2);
                    } else {
                        $group = null;
                        $id = $groupId;
                    }

                    try {
                        $backend->delete(
                            array('role_group', $id),
                            null,
                            $params
                        );

                        if ($group === null) {
                            Notification::success(mt('elasticarmor', 'Group successfully removed'));
                        } else {
                            Notification::success(sprintf(
                                mt('elasticarmor', 'Group "%s" has been removed from role "%s"'),
                                $group,
                                $roleName
                            ));
                        }
                    } catch (Exception $e) {
                        Notification::error($e->getMessage());
                    }
                }

                $redirect = $form->getValue('redirect');
                if (! empty($redirect)) {
                    $form->setRedirectUrl(htmlspecialchars_decode($redirect));
                }

                return true;
            }
        ));
        $form->setUidDisabled();
        $form->setSubmitLabel('btn_submit'); // Required to ensure that isSubmitted() is called
        $form->addElement('hidden', 'group_id', array('required' => true, 'isArray' => true));
        $form->addElement('hidden', 'redirect');
        $form->handleRequest();
    }
}
