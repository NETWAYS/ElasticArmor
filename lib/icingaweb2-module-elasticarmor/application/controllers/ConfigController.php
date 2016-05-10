<?php
/* ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+ */

namespace Icinga\Module\Elasticarmor\Controllers;

use Icinga\Web\Controller;
use Icinga\Module\Elasticarmor\Forms\Configuration\GeneralConfigForm;

class ConfigController extends Controller
{
    /**
     * {@inheritdoc}
     */
    public function init()
    {
        $this->assertPermission('config/modules');
        parent::init();

        $this->view->tabs = $this->Module()->getConfigTabs();
    }

    /**
     * General configuration
     */
    public function generalAction()
    {
        $form = new GeneralConfigForm();
        $form->setIniConfig($this->Config());
        $form->handleRequest();

        $this->view->form = $form;
        $this->getTabs()->activate('elasticarmor/general');
    }
}
