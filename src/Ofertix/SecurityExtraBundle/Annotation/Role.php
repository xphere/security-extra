<?php

namespace Ofertix\SecurityExtraBundle\Annotation;

/**
 * @Annotation
 */
class Role
{
    protected $roles;

    public function __construct(array $values)
    {
        if (!isset($values['roles'])) {
            throw new \InvalidArgumentException(
                'You must define a "roles" attribute for each @Role annotation.'
            );
        }

        $this->setRoles($values['roles']);
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
