<?php
/* ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+ */

namespace Icinga\Module\Elasticarmor\Forms\Configuration;

use Exception;
use Icinga\Data\Extensible;
use Icinga\Web\Form;
use Icinga\Web\Notification;

/**
 * Form for adding one or more users to a role
 */
class AddRoleUserForm extends Form
{
    /**
     * The max size to use for the multi select element
     */
    const MULTISELECT_MAX_SIZE = 20;

    /**
     * The users to choose from
     *
     * @var array
     */
    protected $availableUsers;

    /**
     * The configuration backend to use
     *
     * @var Extensible
     */
    protected $backend;

    /**
     * The role to add users for
     *
     * @var string
     */
    protected $roleName;

    /**
     * Set the users to choose from
     *
     * @param   array   $users
     *
     * @return  $this
     */
    public function setUsers(array $users)
    {
        $this->availableUsers = $users;
        return $this;
    }

    /**
     * Set the configuration backend to use
     *
     * @param   Extensible  $backend
     *
     * @return  $this
     */
    public function setBackend(Extensible $backend)
    {
        $this->backend = $backend;
        return $this;
    }

    /**
     * Set the role to add users for
     *
     * @param   string  $roleName
     *
     * @return  $this
     */
    public function setRoleName($roleName)
    {
        $this->roleName = $roleName;
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function createElements(array $formData)
    {
        if (! empty($this->availableUsers)) {
            $options = array();
            foreach ($this->availableUsers as $user) {
                $options[$user->backend_name . '|' . $user->user_name] = $user->user_name;
            }

            asort($options);
            $this->addElement(
                'multiselect',
                'backend_users',
                array(
                    'multiOptions'  => $options,
                    'label'         => $this->translate('Backend Users'),
                    'description'   => $this->translate(
                        'Select one or more users (fetched from your user backends) to add as role member'
                    ),
                    'size'          => count($options) < static::MULTISELECT_MAX_SIZE
                        ? count($options)
                        : static::MULTISELECT_MAX_SIZE,
                )
            );
        }

        $this->addElement(
            'textarea',
            'users',
            array(
                'required'      => empty($this->availableUsers),
                'label'         => $this->translate('Users'),
                'description'   => $this->translate(
                    'Provide one or more usernames separated by comma to add as role member'
                )
            )
        );

        $this->setSubmitLabel($this->translate('Add'));
    }

    /**
     * {@inheritdoc}
     */
    public function onSuccess()
    {
        $backendUsers = $this->getValue('backend_users') ?: array();
        if (($users = $this->getValue('users'))) {
            $backendUsers = array_merge($backendUsers, array_map('trim', explode(',', $users)));
        }

        if (empty($backendUsers)) {
            $this->info($this->translate(
                'Please provide at least one username, either by choosing one '
                . 'in the list or by manually typing one in the text box below'
            ));
            return false;
        }

        $single = null;
        foreach ($backendUsers as $identifier) {
            if (strpos($identifier, '|') !== false) {
                list($backend, $user) = explode('|', $identifier, 2);
            } else {
                $backend = null;
                $user = $identifier;
            }

            try {
                $this->backend->insert(
                    'role_user',
                    array(
                        'role'      => $this->roleName,
                        'backend'   => $backend,
                        'user'      => $user
                    )
                );
            } catch (Exception $e) {
                Notification::error(sprintf(
                    $this->translate('Failed to add "%s" as member for role "%s"'),
                    $user,
                    $this->roleName
                ));
                $this->error($e->getMessage());
                return false;
            }

            $single = $single === null;
        }

        if ($single) {
            Notification::success(sprintf($this->translate('User "%s" added successfully'), $user));
        } else {
            Notification::success($this->translate('Users added successfully'));
        }

        return true;
    }
}
