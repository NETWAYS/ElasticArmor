<?php
/* ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+ */

namespace Icinga\Module\Elasticarmor\Forms\Configuration;

class PermissionsForm extends RoleForm
{
    /**
     * {@inheritdoc}
     */
    public function createUpdateElements(array $formData)
    {
        if ($this->wasSent($formData)) {
            $permissions = $this->addListEntriesFromSubmit($formData);
        } else {
            $permissions = $this->addListEntriesFromConfig();
        }

        $decorators = static::$defaultElementDecorators;
        array_pop($decorators); // Removes the HtmlTag decorator
        $this->addElement(
            'select',
            'add_permission',
            array(
                'ignore'        => true,
                'label'         => $this->translate('Permission'),
                'multiOptions'  => array_combine($permissions, $permissions), // TODO: Placeholder
                'decorators'    => $decorators
            )
        );
        $this->addElement(
            'submit',
            'btn_add_permission',
            array(
                'type'              => 'submit',
                'formnovalidate'    => 'formnovalidate',
                'label'             => $this->translate('Add'),
                'decorators'        => array('ViewHelper')
            )
        );
        $this->addDisplayGroup(
            array('add_permission', 'btn_add_permission'),
            'add-permission-control-group',
            array(
                'order'         => 0,
                'decorators'    => array(
                    'FormElements',
                    array('HtmlTag', array('tag' => 'div', 'class' => 'control-group'))
                )
            )
        );

        $this->setSubmitLabel($this->translate('Save'));
    }

    /**
     * {@inheritdoc}
     */
    public function setDefault($name, $value)
    {
        if ($name !== 'add_permission') {
            // The select input is intentionally ignored here because each time a user adds a
            // permission we're removing it from the stack and thus cannot be selected again
            parent::setDefault($name, $value);
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getValues($suppressArrayNotation = false)
    {
        $this->data['cluster'] = array_values(parent::getValues($suppressArrayNotation));
        return array('privileges' => $this->data);
    }

    /**
     * Add entries based on the current configuration and return the remaining permissions available for configuration
     *
     * @return  array
     */
    protected function addListEntriesFromConfig()
    {
        $availablePermissions = $this->availablePermissions;
        if ($this->data !== null && isset($this->data['cluster'])) {
            $grantedPermissions = array_flip($this->data['cluster']);

            foreach ($availablePermissions as $permission => $_) {
                if (isset($grantedPermissions[$permission])) {
                    unset($availablePermissions[$permission]);
                    $this->addListEntry($this->generateEntryId(), $permission);
                }
            }
        }

        return array_keys($availablePermissions);
    }

    /**
     * Add entries based on the submitted form data and return the remaining permissions available for configuration
     *
     * @return  array
     */
    protected function addListEntriesFromSubmit(array $formData)
    {
        $grantedPermissions = array();
        $wildcardPermissions = array();
        foreach ($formData as $fieldName => $fieldValue) {
            if (substr($fieldName, 0, 11) === 'permission_') {
                list($_, $ident, $id) = explode('_', $fieldName);
                if ($ident === 'remove') {
                    $grantedPermissions[$fieldValue] = null;
                } elseif ($ident === 'name') {
                    $grantedPermissions[$fieldValue] = $id;
                    if (strpos($fieldValue, '*') !== false) {
                        $wildcardPermissions[] = $fieldValue;
                    }
                }
            } elseif ($fieldName === 'add_permission' && isset($formData['btn_add_permission'])) {
                $grantedPermissions[$fieldValue] = $this->generateEntryId();
                if (strpos($fieldValue, '*') !== false) {
                    $wildcardPermissions[] = $fieldValue;
                }

                if (($reason = $this->isHarmfulPermission($fieldValue)) !== null) {
                    $this->warning(
                        sprintf($this->translate('Permission "%s" is possibly harmful: %s'), $fieldValue, $reason)
                    );
                }
            }
        }

        foreach ($wildcardPermissions as $wildcard) {
            foreach (array_keys($grantedPermissions) as $granted) {
                if ($granted !== $wildcard && preg_match('~' . str_replace('*', '.*', $wildcard) . '~', $granted)) {
                    unset($grantedPermissions[$granted]);
                }
            }
        }

        $availablePermissions = $this->availablePermissions;
        foreach ($availablePermissions as $permission => $_) {
            if (isset($grantedPermissions[$permission])) {
                unset($availablePermissions[$permission]);
                $this->addListEntry($grantedPermissions[$permission], $permission);
            }
        }

        return array_keys($availablePermissions);
    }

    /**
     * Add a new entry to this form
     *
     * @param   int     $id
     * @param   string  $permission
     */
    protected function addListEntry($id, $permission)
    {
        $decorators = static::$defaultElementDecorators;
        array_pop($decorators); // Removes the HtmlTag decorator

        $noteName = 'permission_label_' . $id;
        $hiddenName = 'permission_name_' . $id;
        $buttonName = 'permission_remove_' . $id;
        $this->addElement(
            'note',
            $noteName,
            array(
                'value'         => $permission,
                'decorators'    => $decorators
            )
        );
        $this->addElement(
            'hidden',
            $hiddenName,
            array(
                'value' => $permission
            )
        );
        $this->addElement(
            'button',
            $buttonName,
            array(
                'escape'            => false,
                'type'              => 'submit',
                'value'             => $permission,
                'formnovalidate'    => 'formnovalidate',
                'class'             => 'link-button spinner',
                'label'             => $this->getView()->icon('cancel'),
                'decorators'        => array('ViewHelper')
            )
        );
        $this->addDisplayGroup(
            array($noteName, $buttonName),
            'permission-control-group-' . $id,
            array(
                'decorators'    => array(
                    'FormElements',
                    array('HtmlTag', array('tag' => 'div', 'class' => 'control-group'))
                )
            )
        );
    }

    /**
     * Return a new entry id
     *
     * @return  int
     */
    protected function generateEntryId()
    {
        return mt_rand();
    }
}
