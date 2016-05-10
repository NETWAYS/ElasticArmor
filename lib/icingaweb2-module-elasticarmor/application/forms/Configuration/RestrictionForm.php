<?php
/* ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+ */

namespace Icinga\Module\Elasticarmor\Forms\Configuration;

use UnexpectedValueException;

/**
 * @todo    We're playing with list indices here which may have changed.
 *          Use Elasticsearch's version parameter to avoid consistency issues.
 */
class RestrictionForm extends RoleForm
{
    /**
     * The max size to use for the multi select element
     */
    const MULTISELECT_MAX_SIZE = 20;

    /**
     * The mode of operation
     *
     * @var int
     */
    protected $restrictionMode;

    /**
     * The context of the restriction
     *
     * @var string
     */
    protected $restrictionContext;

    /**
     * The path where the restriction is or should be located
     *
     * @var array
     */
    protected $restrictionPath;

    /**
     * The properties of the restriction
     *
     * @var array
     */
    protected $restrictionData;

    /**
     * Return the context of the restriction
     *
     * @return  string
     */
    public function context()
    {
        if ($this->restrictionContext === null) {
            $this->restrictionContext = $this->identifyContext();
        }

        return $this->restrictionContext;
    }

    /**
     * Return whether it's a index restriction
     *
     * @return  bool
     */
    public function isIndexRestriction()
    {
        return $this->context() === static::INDEX_CONTEXT;
    }

    /**
     * Return whether it's a type restriction
     *
     * @return  bool
     */
    public function isTypeRestriction()
    {
        return $this->context() === static::TYPE_CONTEXT;
    }

    /**
     * Return whether it's a field restriction
     *
     * @return  bool
     */
    public function isFieldRestriction()
    {
        return $this->context() === static::FIELD_CONTEXT;
    }

    /**
     * Create a new restriction
     *
     * @param   string  $path
     * @param   array   $data
     *
     * @return  $this
     */
    public function createRestriction($path, array $data = null)
    {
        $this->restrictionMode = static::MODE_INSERT;
        $this->restrictionPath = explode('.', $path);
        $this->restrictionData = $data;
        return $this;
    }

    /**
     * Update a restriction
     *
     * @param   string  $path
     * @param   array   $data
     *
     * @return  $this
     */
    public function updateRestriction($path, array $data = null)
    {
        $this->restrictionMode = static::MODE_UPDATE;
        $this->restrictionPath = explode('.', $path);
        $this->restrictionData = $data;
        return $this;
    }

    /**
     * Remove a restriction
     *
     * @param   string  $path
     *
     * @return  $this
     */
    public function removeRestriction($path)
    {
        $this->restrictionMode = static::MODE_DELETE;
        $this->restrictionPath = explode('.', $path);
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    protected function onUpdateRequest()
    {
        if ($this->restrictionMode === static::MODE_UPDATE) {
            $data = $this->extract($this->data, $this->restrictionPath);
            if (isset($data['include']) && is_array($data['include'])) {
                $data['include'] = join(', ', $data['include']);
            }

            if (isset($data['exclude']) && is_array($data['exclude'])) {
                $data['exclude'] = join(', ', $data['exclude']);
            }

            $this->populate($data);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function createUpdateElements(array $formData)
    {
        if ($this->restrictionMode === static::MODE_INSERT) {
            $this->createInsertRestrictionElements($formData);
        } elseif ($this->restrictionMode === static::MODE_UPDATE) {
            $this->createUpdateRestrictionElements($formData);
        } else {
            $this->createDeleteRestrictionElements($formData);
        }
    }

    /**
     * Create and add elements to this form to create a new restriction
     *
     * @param   array   $formData   The data sent by the user
     */
    protected function createInsertRestrictionElements(array $formData)
    {
        $this->addElement( // TODO: Validator
            'text',
            'include',
            array(
                'required'  => true,
                'label'     => $this->translate('Include')
            )
        );

        if (! $this->isTypeRestriction()) {
            $this->addElement( // TODO: Validator
                'text',
                'exclude',
                array(
                    'allowEmpty'    => true,
                    'label'         => $this->translate('Exclude')
                )
            );
        }

        $availablePermissions = $this->identifyPermissions();
        $this->addElement(
            'multiselect',
            'permissions',
            array(
                'size'          => count($availablePermissions) < static::MULTISELECT_MAX_SIZE
                    ? count($availablePermissions)
                    : static::MULTISELECT_MAX_SIZE,
                'multiOptions'  => array_combine($availablePermissions, $availablePermissions),
                'label'         => $this->translate('Permissions')
            )
        );

        $this->setSubmitLabel($this->translate('Create Restriction'));
    }

    /**
     * Create and add elements to this form to update a restriction
     *
     * @param   array   $formData   The data sent by the user
     */
    public function createUpdateRestrictionElements(array $formData)
    {
        $this->createInsertRestrictionElements($formData);
        $this->setSubmitLabel($this->translate('Save'));
    }

    /**
     * Create and add elements to this form to remove a restriction
     *
     * @param   array   $formData   The data sent by the user
     */
    public function createDeleteRestrictionElements(array $formData)
    {
        $this->setSubmitLabel($this->translate('Remove Restriction'));
    }

    /**
     * {@inheritdoc}
     */
    public function getValues($suppressArrayNotation = false)
    {
        if ($this->restrictionMode === static::MODE_DELETE) {
            $this->discard($this->data, $this->restrictionPath);
        } else {
            $values = array_filter(parent::getValues($suppressArrayNotation));
            if (isset($values['include'])) {
                $values['include'] = array_map('trim', explode(',', $values['include']));
            }

            if (isset($values['exclude'])) {
                $values['exclude'] = array_map('trim', explode(',', $values['exclude']));
            }

            $this->inject($this->data, $this->restrictionPath, $values);
        }

        return array('privileges' => $this->data);
    }

    /**
     * Identify and return the context of the restriction which is being configured
     *
     * @return  string
     *
     * @throws  UnexpectedValueException    In case of an invalid context
     */
    protected function identifyContext()
    {
        $context = null;
        $path = $this->restrictionPath;
        while ($context === null || is_numeric($context)) {
            $context = array_pop($path);
        }

        switch ($context)
        {
            case static::INDEX_CONTEXT:
            case static::TYPE_CONTEXT:
            case static::FIELD_CONTEXT:
                return $context;
            default:
                throw new UnexpectedValueException(sprintf('"%s" is not a valid context'), $context);
        }
    }

    /**
     * Identify and return all available permissions matching the current context
     *
     * @return  array
     */
    protected function identifyPermissions()
    {
        $permissions = array();
        foreach ($this->availablePermissions as $permission => $context) {
            if ($this->isIndexRestriction() && $context !== static::CLUSTER_CONTEXT ||
                $this->isTypeRestriction() && in_array($context, array(static::TYPE_CONTEXT, static::FIELD_CONTEXT)) ||
                $this->isFieldRestriction() && $context === static::FIELD_CONTEXT
            ) {
                $permissions[] = $permission;
            }
        }

        return $permissions;
    }

    /**
     * Inject the given restriction into the current privilege stack
     *
     * @param   array   $data
     * @param   array   $path
     * @param   array   $restriction
     */
    protected function inject(array &$data, array $path, array $restriction)
    {
        $key = array_shift($path);
        if (! empty($path)) {
            $this->inject($data[$key], $path, $restriction);
        } elseif (is_numeric($key)) {
            $data[$key] = $restriction;
        } else {
            $data[$key][] = $restriction;
        }
    }

    /**
     * Extract a restriction from the current privilege stack
     *
     * @param   array   $data
     * @param   array   $path
     *
     * @return  array
     */
    protected function extract(array $data, array $path)
    {
        $key = array_shift($path);
        if (! empty($path)) {
            return $this->extract($data[$key], $path);
        } else {
            return $data[$key];
        }
    }

    /**
     * Remove a restriction from the current privilege stack
     *
     * @param   array   $data
     * @param   array   $path
     */
    protected function discard(array &$data, array $path)
    {
        $key = array_shift($path);
        if (! empty($path)) {
            return $this->discard($data[$key], $path);
        } else {
            unset($data[$key]);
            $data = array_values($data);
        }
    }
}
