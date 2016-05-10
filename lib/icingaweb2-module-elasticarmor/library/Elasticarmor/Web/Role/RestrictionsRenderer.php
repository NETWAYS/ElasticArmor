<?php
/* ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+ */

namespace Icinga\Module\Elasticarmor\Web\Role;

use Exception;
use Icinga\Application\Icinga;
use Icinga\Exception\IcingaException;
use Icinga\Web\View;

class RestrictionsRenderer
{
    /**
     * The role for which restrictions are being rendered
     *
     * @var string
     */
    protected $roleName;

    /**
     * The restrictions being rendered
     *
     * @var array
     */
    protected $privileges;

    /**
     * View
     *
     * @var View
     */
    protected $view;

    /**
     * The rendered HTML
     *
     * @var array
     */
    protected $html;

    /**
     * Create a new RestrictionsRenderer
     *
     * @param   string  $roleName       The role for which to render restrictions
     * @param   array   $privileges     The restrictions to render
     */
    public function __construct($roleName, array $privileges)
    {
        $this->privileges = $privileges;
        $this->roleName = $roleName;
        $this->html = array();
    }

    /**
     * Return the view
     *
     * @return  View
     */
    public function view()
    {
        if ($this->view === null) {
            $this->setView(Icinga::app()->getViewRenderer()->view);
        }

        return $this->view;
    }

    /**
     * Set the view
     *
     * @param   View    $view
     *
     * @return  $this
     */
    public function setView(View $view)
    {
        $this->view = $view;
        return $this;
    }

    /**
     * Render and return the restrictions
     *
     * @return  string
     */
    public function render()
    {
        $this->html('<dl>');

        $this->renderTerm($this->view()->translate('Indices'));
        if (isset($this->privileges['indices'])) {
            foreach ($this->privileges['indices'] as $id => $restriction) {
                $this->renderIndexRestriction("indices.$id", $restriction);
            }
        }
        $this->renderCreateLink('indices', $this->view()->translate('Create a new index restriction'));

        if (isset($this->privileges['indices']) && !empty($this->privileges['indices'])) {
            $this->renderTerm($this->view()->translate('Types'));
            if (isset($this->privileges['types'])) {
                foreach ($this->privileges['types'] as $id => $restriction) {
                    $this->renderTypeRestriction("types.$id", $restriction);
                }
            }
            $this->renderCreateLink('types', $this->view()->translate('Create a new type restriction'));

            if (isset($this->privileges['types']) && !empty($this->privileges['types'])) {
                $this->renderTerm($this->view()->translate('Fields'));
                if (isset($this->privileges['fields'])) {
                    foreach ($this->privileges['fields'] as $id => $restriction) {
                        $this->renderFieldRestriction("fields.$id", $restriction);
                    }
                }
                $this->renderCreateLink('fields', $this->view()->translate('Create a new field restriction'));
            }
        }

        return join("\n", $this->html('</dl>'));
    }

    /**
     * Render and return the restrictions
     *
     * @return  string
     */
    public function __toString()
    {
        try {
            return $this->render();
        } catch (Exception $e) {
            return IcingaException::describe($e);
        }
    }

    /**
     * Render the given HTML and return the HTML rendered so far
     *
     * @param   string  $html
     *
     * @return  array
     */
    protected function html($html = null)
    {
        if ($html !== null) {
            $this->html[] = $html;
        }

        return $this->html;
    }

    /**
     * Render the given term
     *
     * @param   string  $term
     */
    protected function renderTerm($term)
    {
        $this->html('<dt>');
        $this->html($term);
        $this->html('</dt>');
    }

    /**
     * Render the given description
     *
     * @param   string  $description
     */
    protected function renderDescription($description)
    {
        $this->html('<dd>');
        $this->html($description);
        $this->html('</dd>');
    }

    /**
     * Render a link to create a new restriction
     *
     * @param   string  $path   The path where to create the restriction
     * @param   string  $title  The title to use for the link
     */
    protected function renderCreateLink($path, $title)
    {
        $this->renderDescription($this->view()->qlink(
            $title,
            'elasticarmor/roles/restrictions-create',
            array(
                'role'  => $this->roleName,
                'path'  => $path
            ),
            array(
                'icon'              => 'plus',
                'title'             => $title,
                'data-base-target'  => '_next',
                'class'             => 'create-link'
            )
        ));
    }

    /**
     * Render a link to update a restriction
     *
     * @param   string  $path   The path where the restriction is located
     * @param   string  $title  The title to use for the link
     */
    protected function renderUpdateLink($path, $title)
    {
        $this->html($this->view()->qlink(
            null,
            'elasticarmor/roles/restrictions-update',
            array(
                'role'  => $this->roleName,
                'path'  => $path
            ),
            array(
                'icon'              => 'edit',
                'title'             => $title,
                'data-base-target'  => '_next',
                'class'             => 'update-link'
            )
        ));
    }

    /**
     * Render a link to remove a restriction
     *
     * @param   string  $path   The path where the restriction is located
     * @param   string  $title  The title to use for the link
     */
    protected function renderRemoveLink($path, $title)
    {
        $this->html($this->view()->qlink(
            null,
            'elasticarmor/roles/restrictions-remove',
            array(
                'role'  => $this->roleName,
                'path'  => $path
            ),
            array(
                'icon'              => 'cancel',
                'title'             => $title,
                'data-base-target'  => '_next',
                'class'             => 'remove-link',
            )
        ));
    }

    /**
     * Render the given index restriction
     *
     * @param   string  $path           The path where the restriction is located
     * @param   array   $restriction    The restriction to render
     */
    protected function renderIndexRestriction($path, array $restriction)
    {
        $this->html('<dd>');
         $this->renderRemoveLink($path, $this->view()->translate('Remove this index restriction'));
        $this->renderUpdateLink($path, $this->view()->translate('Edit this index restriction'));
        $this->html('<dl class="table-row-selectable">');
        foreach ($restriction as $key => $values) {
            if ($key === 'include') {
                $this->renderTerm($this->view()->translate('Include'));
            } elseif ($key === 'exclude') {
                $this->renderTerm($this->view()->translate('Exclude'));
            } elseif ($key === 'permissions') {
                $this->renderTerm($this->view()->translate('Permissions'));
            } else {
                continue;
            }

            if (is_string($values)) {
                $values = explode(',', $values);
            }

            foreach ($values as $description) {
                $this->renderDescription($description);
            }
        }

        $this->renderTerm($this->view()->translate('Types'));
        if (isset($restriction['types'])) {
            foreach ($restriction['types'] as $id => $typeRestriction) {
                $this->renderTypeRestriction("$path.types.$id", $typeRestriction);
            }
        }
        $this->renderCreateLink("$path.types", $this->view()->translate('Create a new type restriction'));

        $this->html('</dl>');
        $this->html('</dd>');
    }

    /**
     * Render the given type restriction
     *
     * @param   string  $path           The path where the restriction is located
     * @param   array   $restriction    The restriction to render
     */
    protected function renderTypeRestriction($path, array $restriction)
    {
        $this->html('<dd>');
        $this->renderRemoveLink($path, $this->view()->translate('Remove this type restriction'));
        $this->renderUpdateLink($path, $this->view()->translate('Edit this type restriction'));
        $this->html('<dl class="table-row-selectable">');
        foreach ($restriction as $key => $values) {
            if ($key === 'include') {
                $this->renderTerm($this->view()->translate('Include'));
            } elseif ($key === 'permissions') {
                $this->renderTerm($this->view()->translate('Permissions'));
            } else {
                continue;
            }

            if (is_string($values)) {
                $values = explode(',', $values);
            }

            foreach ($values as $description) {
                $this->renderDescription($description);
            }
        }

        $this->renderTerm($this->view()->translate('Fields'));
        if (isset($restriction['fields'])) {
            foreach ($restriction['fields'] as $id => $typeRestriction) {
                $this->renderFieldRestriction("$path.fields.$id", $typeRestriction);
            }
        }
        $this->renderCreateLink("$path.fields", $this->view()->translate('Create a new field restriction'));

        $this->html('</dl>');
        $this->html('</dd>');
    }

    /**
     * Render the given field restriction
     *
     * @param   string  $path           The path where the restriction is located
     * @param   array   $restriction    The restriction to render
     */
    protected function renderFieldRestriction($path, array $restriction)
    {
        $this->html('<dd>');
        $this->renderRemoveLink($path, $this->view()->translate('Remove this field restriction'));
        $this->renderUpdateLink($path, $this->view()->translate('Edit this field restriction'));
        $this->html('<dl>');
        foreach ($restriction as $key => $values) {
            if ($key === 'include') {
                $this->renderTerm($this->view()->translate('Include'));
            } elseif ($key === 'exclude') {
                $this->renderTerm($this->view()->translate('Exclude'));
            } elseif ($key === 'permissions') {
                $this->renderTerm($this->view()->translate('Permissions'));
            } else {
                continue;
            }

            if (is_string($values)) {
                $values = explode(',', $values);
            }

            foreach ($values as $description) {
                $this->renderDescription($description);
            }
        }

        $this->html('</dl>');
        $this->html('</dd>');
    }
}
