<?php
/* ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+ */

namespace Icinga\Module\Elasticarmor\Controllers;

use Icinga\Web\Controller;
use Icinga\Web\Url;
use Icinga\Module\Elasticarmor\Configuration\Backend\ElasticsearchBackend;
use Icinga\Module\Elasticarmor\Forms\Configuration\RestrictionForm;

class RestrictionsController extends Controller
{
    /**
     * Return the configuration backend to use
     */
    protected function getConfigurationBackend()
    {
        return ElasticsearchBackend::fromConfig();
    }

    /**
     * Create a new restriction
     */
    public function createAction()
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

        $this->getTabs()->add('restrictions/create', array(
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
    public function updateAction()
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

        $this->getTabs()->add('restrictions/update', array(
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
    public function removeAction()
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

        $this->getTabs()->add('restrictions/remove', array(
            'active'    => true,
            'label'     => $this->translate('Remove Restriction'),
            'url'       => Url::fromRequest()
        ));

        $this->view->form = $form;
        $this->render('form');
    }
}
