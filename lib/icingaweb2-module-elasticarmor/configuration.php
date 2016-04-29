<?php
/* ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+ */

/** @var $this \Icinga\Application\Modules\Module */

$menuSection = $this->menuSection('ElasticArmor')
    ->setIcon('lock');

$menuSection->add(N_('Roles'))
    ->setUrl('elasticarmor/roles/list');
