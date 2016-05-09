<?php
/* ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+ */

namespace Icinga\Module\Elasticarmor\Forms\Configuration;

use Icinga\Forms\ConfigForm;

class GeneralConfigForm extends ConfigForm
{
    /**
     * Initialize this form
     */
    public function init()
    {
        $this->setName('form_config_elasticarmor_general');
        $this->setSubmitLabel($this->translate('Save Changes'));
    }

    /**
     * {@inheritdoc}
     */
    public function createElements(array $formData)
    {
        $this->addElement(
            'text',
            'backend_index',
            array(
                'placeholder'   => '.elasticarmor',
                'label'         => $this->translate('Configuration Index'),
                'description'   => $this->translate(
                    'The name of the index where the ElasticArmor authentication configuration is stored'
                )
            )
        );
    }
}
