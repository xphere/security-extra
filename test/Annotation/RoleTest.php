<?php

namespace Ofertix\SecurityExtraBundle\Tests\Annotation;

use PHPUnit_Framework_TestCase;
use Ofertix\SecurityExtraBundle\Annotation\Role;

/**
 * Class RoleTest
 */
class RoleTest extends PHPUnit_Framework_TestCase
{
    /**
     * @dataProvider providerValid
     */
    public function testValid($data)
    {
        $annotation = new Role($data);

        $this->assertNotNull($annotation);
    }

    /**
     * @dataProvider providerValid
     */
    public function testRoles($data, $expectedRoles)
    {
        $annotation = new Role($data);

        $roles = $annotation->getRoles();
        sort($roles);
        sort($expectedRoles);

        $this->assertEquals($expectedRoles, $roles);
    }

    public function providerValid()
    {
        return array(
            'single-role-in-string' => array(
                array('name' => 'parameter', 'roles' => 'ROLE_USER', ),
                array('ROLE_USER', ),
            ),
            'multiple-roles-in-comma-separated-string' => array(
                array('name' => 'parameter', 'roles' => 'ROLE_USER,ROLE_SUPERUSER', ),
                array('ROLE_USER', 'ROLE_SUPERUSER', ),
            ),
            'multiple-roles-in-comma-separated-string-with-spaces' => array(
                array('name' => 'parameter', 'roles' => 'ROLE_USER , ROLE_SUPERUSER', ),
                array('ROLE_USER', 'ROLE_SUPERUSER', ),
            ),
            'single-role-in-array' => array(
                array('name' => 'parameter', 'roles' => array('ROLE_USER', ) ),
                array('ROLE_USER', ),
            ),
            'multiple-roles-in-array' => array(
                array('name' => 'parameter', 'roles' => array('ROLE_USER', 'ROLE_SUPERUSER', ) ),
                array('ROLE_USER', 'ROLE_SUPERUSER', ),
            ),
        );
    }

    /**
     * @expectedException \InvalidArgumentException
     * @dataProvider providerInvalid
     */
    public function testInvalid($data)
    {
        $annotation = new Role($data);
        // Execution should not reach next line
        $this->assertNotNull($annotation);
    }

    public function providerInvalid()
    {
        return array(
            'empty-data' => array(
                array(),
            ),
            'invalid-keys' => array(
                array('name' => 'parameter'),
            ),
        );
    }
}
