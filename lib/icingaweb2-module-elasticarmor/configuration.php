<?php
/* ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+ */

/** @var $this \Icinga\Application\Modules\Module */

$menuSection = $this->menuSection('Elasticsearch')
    ->add(N_('Authentication'))
    ->setIcon('lock')
    ->setPriority(820)
    ->setUrl('elasticarmor/roles/list');
