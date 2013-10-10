<?php

namespace Ofertix\SecurityExtraBundle\Annotation;

/**
 * @Annotation
 */
class Param
{
    protected $name;
    protected $roles = array();

    public function __construct(array $values)
    {
        if (isset($values['value'])) {
            $values['roles'] = $values['value'];
        }

        if (!isset($values['name'])) {
            throw new \InvalidArgumentException(
                'You must define a "name" attribute for each @Param annotation.'
            );
        }

        if (!isset($values['roles'])) {
            throw new \InvalidArgumentException(
                'You must define a "roles" attribute for each @Param annotation.'
            );
        }

        $this
            ->setName($values['name'])
            ->setRoles($values['roles'])
        ;
    }

    public function getName()
    {
        return $this->name;
    }

    public function setName($name)
    {
        $this->name = $name;

        return $this;
    }

    public function getRoles()
    {
        return $this->roles;
    }

    public function setRoles($roles)
    {
        $this->roles = array_filter(array_map('trim', is_array($roles) ? $roles : explode(',', $roles)));

        return $this;
    }
}
