<?php

namespace Ofertix\SecurityExtraBundle\Tests\Annotation;

use PHPUnit_Framework_TestCase;
use Ofertix\SecurityExtraBundle\Annotation\Param;

/**
 * Class ParamTest
 */
class ParamTest extends PHPUnit_Framework_TestCase
{
    /**
     * @dataProvider providerValid
     */
    public function testValid($data)
    {
        $annotation = new Param($data);

        $this->assertNotNull($annotation);
    }

    /**
     * @dataProvider providerValid
     */
    public function testParameterName($data, $parameterName)
    {
        $annotation = new Param($data);

        $this->assertEquals($parameterName, $annotation->getName());
    }

    /**
     * @dataProvider providerValid
     */
    public function testRoles($data, $_, $expectedRoles)
    {
        $annotation = new Param($data);
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
                'parameter',
                array('ROLE_USER', ),
            ),
            'multiple-roles-in-comma-separated-string' => array(
                array('name' => 'parameter', 'roles' => 'ROLE_USER,ROLE_SUPERUSER', ),
                'parameter',
                array('ROLE_USER', 'ROLE_SUPERUSER', ),
            ),
            'multiple-roles-in-comma-separated-string-with-spaces' => array(
                array('name' => 'parameter', 'roles' => 'ROLE_USER , ROLE_SUPERUSER', ),
                'parameter',
                array('ROLE_USER', 'ROLE_SUPERUSER', ),
            ),
            'single-role-in-array' => array(
                array('name' => 'parameter', 'roles' => array('ROLE_USER', ) ),
                'parameter',
                array('ROLE_USER', ),
            ),
            'multiple-roles-in-array' => array(
                array('name' => 'parameter', 'roles' => array('ROLE_USER', 'ROLE_SUPERUSER', ) ),
                'parameter',
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
        $annotation = new Param($data);
        // Execution should not reach next line
        $this->assertNotNull($annotation);
    }

    public function providerInvalid()
    {
        return array(
            'empty-data' => array(
                array(),
            ),
            'parameter-but-not-role' => array(
                array('name' => 'parameter'),
            ),
            'role-but-not-parameter' => array(
                array('roles' => 'ROLE_USER', ),
            ),
        );
    }
}
