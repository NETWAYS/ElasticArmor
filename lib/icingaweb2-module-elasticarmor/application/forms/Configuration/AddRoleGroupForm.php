<?php
/* ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+ */

namespace Icinga\Module\Elasticarmor\Forms\Configuration;

use Exception;
use Icinga\Data\Extensible;
use Icinga\Web\Form;
use Icinga\Web\Notification;

/**
 * Form for adding one or more groups to a role
 */
class AddRoleGroupForm extends Form
{
    /**
     * The max size to use for the multi select element
     */
    const MULTISELECT_MAX_SIZE = 20;

    /**
     * The groups to choose from
     *
     * @var array
     */
    protected $availableGroups;

    /**
     * The configuration backend to use
     *
     * @var Extensible
     */
    protected $backend;

    /**
     * The role to add groups for
     *
     * @var string
     */
    protected $roleName;

    /**
     * Set the groups to choose from
     *
     * @param   array   $groups
     *
     * @return  $this
     */
    public function setGroups(array $groups)
    {
        $this->availableGroups = $groups;
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
     * Set the role to add groups for
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
        if (! empty($this->availableGroups)) {
            $options = array();
            foreach ($this->availableGroups as $group) {
                $options[$group->backend_name . '|' . $group->group_name] = $group->group_name;
            }

            $this->addElement(
                'multiselect',
                'backend_groups',
                array(
                    'multiOptions'  => $options,
                    'label'         => $this->translate('Backend Groups'),
                    'description'   => $this->translate(
                        'Select one or more groups (fetched from your group backends) to add as role member'
                    ),
                    'size'          => count($options) < static::MULTISELECT_MAX_SIZE
                        ? count($options)
                        : static::MULTISELECT_MAX_SIZE,
                )
            );
        }

        $this->addElement(
            'textarea',
            'groups',
            array(
                'required'      => empty($this->availableGroups),
                'label'         => $this->translate('Groups'),
                'description'   => $this->translate(
                    'Provide one or more groups separated by comma to add as role member'
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
        $backendGroups = $this->getValue('backend_groups') ?: array();
        if (($users = $this->getValue('groups'))) {
            $backendGroups = array_merge($backendGroups, array_map('trim', explode(',', $users)));
        }

        if (empty($backendGroups)) {
            $this->info($this->translate(
                'Please provide at least one group, either by choosing one in'
                . ' the list or by manually typing one in the text box below'
            ));
            return false;
        }

        $single = null;
        foreach ($backendGroups as $identifier) {
            if (strpos($identifier, '|') !== false) {
                list($backend, $group) = explode('|', $identifier, 2);
            } else {
                $backend = null;
                $group = $identifier;
            }

            try {
                $this->backend->insert(
                    'role_group',
                    array(
                        'role'      => $this->roleName,
                        'backend'   => $backend,
                        'group'     => $group
                    )
                );
            } catch (Exception $e) {
                Notification::error(sprintf(
                    $this->translate('Failed to add "%s" as member for role "%s"'),
                    $group,
                    $this->roleName
                ));
                $this->error($e->getMessage());
                return false;
            }

            $single = $single === null;
        }

        if ($single) {
            Notification::success(sprintf($this->translate('Group "%s" added successfully'), $group));
        } else {
            Notification::success($this->translate('Groups added successfully'));
        }

        return true;
    }
}
