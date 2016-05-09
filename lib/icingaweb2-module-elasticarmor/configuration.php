<?php
/* ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+ */

/** @var $this \Icinga\Application\Modules\Module */

$menuSection = $this->menuSection('Elasticsearch')
    ->add(N_('Authentication'))
    ->setIcon('lock')
    ->setPriority(820)
    ->setUrl('elasticarmor/roles/list');

$this->provideConfigTab('elasticarmor/general', array(
    'title' => $this->translate('Adjust the general configuration of the ElasticArmor module'),
    'label' => $this->translate('General'),
    'url'   => 'config/general'
));