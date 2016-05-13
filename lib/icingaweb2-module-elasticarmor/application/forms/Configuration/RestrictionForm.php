<?php
/* ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+ */

namespace Icinga\Module\Elasticarmor\Forms\Configuration;

use UnexpectedValueException;
use Icinga\Web\Url;

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
     * {@inheritdoc}
     */
    public function init()
    {
        $this->setProtectIds(false);
        $this->setName('elasticarmor_restriction_form');
    }

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
        $discoverParams = array();
        if ($this->isIndexRestriction()) {
            $includeDescription = $this->translate(
                'The indices this restriction permits access to. Use * as a wildcard'
            );
            $excludeDescription = $this->translate(
                'The indices to which this restriction explicitly forbids access. Use * as a wildcard'
            );
        } elseif ($this->isTypeRestriction()) {
            $includeDescription = $this->translate('The document types this restriction permits access to');
            $discoverParams['indexFilter'] = $this->createFilterString(
                $this->restrictionMode === static::MODE_INSERT
                    ? array_slice($this->restrictionPath, 0, -1)
                    : $this->restrictionPath,
                static::INDEX_CONTEXT
            );
        } elseif ($this->isFieldRestriction()) {
            $includeDescription = $this->translate(
                'The fields this restriction permits access to. Use * as a wildcard'
            );
            $excludeDescription = $this->translate(
                'The fields to which this restriction explicitly forbids access. Use * as a wildcard'
            );
            $discoverParams['indexFilter'] = $this->createFilterString(
                $this->restrictionMode === static::MODE_INSERT
                    ? array_slice($this->restrictionPath, 0, -3)
                    : array_slice($this->restrictionPath, 0, -2),
                static::INDEX_CONTEXT
            );
            $discoverParams['typeFilter'] = $this->createFilterString(
                $this->restrictionMode === static::MODE_INSERT
                    ? array_slice($this->restrictionPath, 0, -1)
                    : $this->restrictionPath,
                static::TYPE_CONTEXT
            );
        }

        $this->addElement( // TODO: Validator
            'text',
            'include',
            array(
                'required'          => true,
                'autosubmit'        => true,
                'autocomplete'      => 'off',
                'autocorrect'       => 'off',
                'autocapitalize'    => 'off',
                'spellcheck'        => 'false',
                'label'             => $this->translate('Include'),
                'description'       => $includeDescription
            )
        )->getElement('include')->setAttrib('class', 'include');

        if (! $this->isTypeRestriction()) {
            $this->addElement( // TODO: Validator
                'text',
                'exclude',
                array(
                    'allowEmpty'        => true,
                    'autosubmit'        => true,
                    'autocomplete'      => 'off',
                    'autocorrect'       => 'off',
                    'autocapitalize'    => 'off',
                    'spellcheck'        => 'false',
                    'label'             => $this->translate('Exclude'),
                    'description'       => $excludeDescription
                )
            )->getElement('exclude')->setAttrib('class', 'exclude');
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
                'label'         => $this->translate('Permissions'),
                'description'   => $this->translate(
                    'The permissions this restriction grants within its scope. '
                    . 'Leave empty to inherit permissions from the parent scope'
                )
            )
        );

        $this->addElement(
            'hidden',
            'discover_url',
            array(
                'disabled'  => 'disabled',
                'value'     => Url::fromPath('elasticarmor/restrictions/discover', $discoverParams)->getAbsoluteUrl()
            )
        );
        $this->addElement(
            'note',
            'discovery_result',
            array(
                'value'         => '<div id="discovery"></div>',
                'decorators'    => array('ViewHelper')
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

    /**
     * Create and return a filter string
     *
     * @param   array   $path           The path to the restriction the filter string should apply to
     * @param   string  $desiredScope   The desired restriction scope
     *
     * @return  string
     */
    protected function createFilterString(array $path, $desiredScope)
    {
        if (! empty($path)) {
            $restrictions = array($this->extract($this->data, $path));
        } else {
            $restrictions = $this->data[$desiredScope];
        }

        $parts = array();
        foreach ($restrictions as $restriction) {
            if (is_array($restriction['include'])) {
                $parts = array_merge($parts, $restriction['include']);
            } else {
                $parts = array_merge(
                    $parts,
                    array_map('trim', explode(',', $restriction['include']))
                );
            }

            if (isset($restriction['exclude'])) {
                if (is_array($restriction['exclude'])) {
                    $parts = array_merge(
                        $restriction['include'],
                        array_map(
                            function ($exclude) { return '-' . $exclude; },
                            $restriction['exclude']
                        )
                    );
                } else {
                    $parts = array_merge(
                        $parts,
                        array_map(
                            function ($exclude) { return '-' . trim($exclude); },
                            explode(',', $restriction['exclude'])
                        )
                    );
                }
            }
        }

        return join(',', $parts);
    }
}
