<?php
/* ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+ */

namespace Icinga\Module\Elasticarmor\Controllers;

use Icinga\Web\Controller;
use Icinga\Web\Notification;
use Icinga\Web\Url;
use Icinga\Module\Elasticarmor\Configuration\Backend\ElasticsearchBackend;
use Icinga\Module\Elasticarmor\Forms\Configuration\RestrictionForm;
use Icinga\Module\Elasticsearch\RestApi\GetIndicesApiRequest;
use Icinga\Module\Elasticsearch\RestApi\GetMappingApiRequest;

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

    /**
     * Run a discovery
     */
    public function discoverAction()
    {
        $includes = $this->params->get('include', '');
        $excludes = $this->params->get('exclude', '');
        $indexFilter = $this->params->get('indexFilter');
        $typeFilter = $this->params->get('typeFilter');

        if ($typeFilter) {
            $this->view->scope = 'fields';
            $results = $this->discoverFields($this->getConfigurationBackend(), $indexFilter, $typeFilter);
        } elseif ($indexFilter) {
            $this->view->scope = 'types';
            $results = $this->discoverTypes($this->getConfigurationBackend(), $indexFilter);
        } else {
            $this->view->scope = 'indices';
            $results = $this->discoverIndices($this->getConfigurationBackend());
        }

        list($matches, $mismatches) = $this->applyPatterns(
            array_map('trim', explode(',', $includes)),
            array_map('trim', explode(',', $excludes)),
            $results
        );

        $this->view->matches = $matches;
        $this->view->mismatches = $mismatches;
        $this->view->totalResults = count($results);
    }

    /**
     * Return all index names and their aliases as array
     *
     * @param   ElasticsearchBackend    $backend
     *
     * @return  array
     */
    protected function discoverIndices($backend)
    {
        $response = $backend->getDataSource()->request(
            new GetIndicesApiRequest(array('*', '-' . $backend->getIndex()), array('_aliases'))
        );
        if (! $response->isSuccess()) {
            Notification::error(sprintf(
                $this->translate('Failed to discover indices: %s'),
                $backend->getDataSource()->renderErrorMessage($response)
            ));
            return array();
        }

        $indices = array();
        foreach ($response->json() as $indexName => $settings) {
            $indices[] = $indexName;
            if (isset($settings['aliases'])) {
                $indices = array_merge($indices, array_keys($settings['aliases']));
            }
        }

        return $indices;
    }

    /**
     * Return all document type names associated with the given indices
     *
     * @param   ElasticsearchBackend    $backend
     * @param   string                  $indexFilter
     *
     * @return  array
     */
    protected function discoverTypes($backend, $indexFilter)
    {
        $indices = array($indexFilter);
        if (strpos($indexFilter, '*') !== false) {
            $indices[] = '-' . $backend->getIndex();
        }

        $response = $backend->getDataSource()->request(new GetIndicesApiRequest($indices, array('_mappings')));
        if (! $response->isSuccess()) {
            Notification::error(sprintf(
                $this->translate('Failed to discover document types: %s'),
                $backend->getDataSource()->renderErrorMessage($response)
            ));
            return array();
        }

        $types = array();
        foreach ($response->json() as $settings) {
            if (isset($settings['mappings'])) {
                foreach ($settings['mappings'] as $typeName => $_) {
                    if (substr($typeName, 0, 1) !== '_') {
                        $types[$typeName] = null;
                    }
                }
            }
        }

        $types = array_keys($types);
        return $types;
    }

    /**
     * Return all field names associated with the given indices and types
     *
     * @param   ElasticsearchBackend    $backend
     * @param   string                  $indexFilter
     * @param   string                  $typeFilter
     *
     * @return  array
     */
    protected function discoverFields($backend, $indexFilter, $typeFilter)
    {
        $indices = array($indexFilter);
        if (strpos($indexFilter, '*') !== false) {
            $indices[] = '-' . $backend->getIndex();
        }

        $response = $backend->getDataSource()->request(new GetMappingApiRequest($indices, array($typeFilter)));
        if (! $response->isSuccess()) {
            Notification::error(sprintf(
                $this->translate('Failed to discover fields: %s'),
                $backend->getDataSource()->renderErrorMessage($response)
            ));
            return array();
        }

        $fields = array();
        foreach ($response->json() as $settings) {
            if (isset($settings['mappings'])) {
                foreach ($settings['mappings'] as $mapping) {
                    if (isset($mapping['properties'])) {
                        $this->flattenProperties($mapping['properties'], '', $fields);
                    }
                }
            }
        }

        $fields = array_keys($fields);
        return $fields;
    }

    /**
     * Return the given properties as flattened array
     *
     * @param   array   $properties
     * @param   string  $prefix
     * @param   array   $propertyMap
     *
     * @return  array
     */
    protected function flattenProperties(array $properties, $prefix, array & $propertyMap)
    {
        foreach ($properties as $propertyName => $propertySettings) {
            $propertyMap["$prefix$propertyName"] = null;
            if (isset($propertySettings['properties'])) {
                $this->flattenProperties($propertySettings['properties'], "$prefix$propertyName.", $propertyMap);
            }
            if (isset($propertySettings['fields'])) {
                $this->flattenProperties($propertySettings['fields'], "$prefix$propertyName.", $propertyMap);
            }
        }
    }

    /**
     * Identify and return what is matched and mismatched by the given patterns
     *
     * @param   array   $includes
     * @param   array   $excludes
     * @param   array   $names
     *
     * @return  array
     */
    protected function applyPatterns($includes, $excludes, $names)
    {
        if (empty($includes)) {
            return array(array(), $names);
        }

        $matches = array();
        $mismatches = array();
        foreach ($names as $name) {
            foreach ($includes as $include) {
                if (preg_match('/^' . str_replace('\*', '.*', preg_quote($include, '/')) . '$/', $name)) {
                    foreach ($excludes as $exclude) {
                        if (preg_match('/^' . str_replace('\*', '.*', preg_quote($exclude, '/')) . '$/', $name)) {
                            $mismatches[$name] = true;
                            unset($matches[$name]);
                            break;
                        } elseif (! isset($mismatches[$name])) {
                            $matches[$name] = null;
                            unset($mismatches[$name]);
                        }
                    }
                } elseif (! array_key_exists($name, $matches) && !isset($mismatches[$name])) {
                    $mismatches[$name] = null;
                }
            }
        }

        $matches = array_keys($matches);
        $mismatches = array_keys($mismatches);

        natsort($matches);
        natsort($mismatches);
        return array($matches, $mismatches);
    }
}
