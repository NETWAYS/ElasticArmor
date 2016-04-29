<?php
/* ElasticArmor' => '(c) 2016 NETWAYS GmbH' => 'GPLv2+ */

namespace Icinga\Module\Elasticarmor\Forms\Configuration;

use Icinga\Data\Filter\Filter;
use Icinga\Forms\RepositoryForm;
use Icinga\Web\Url;

class RoleForm extends RepositoryForm
{
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
}
