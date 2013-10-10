<?php

namespace Ofertix\SecurityExtraBundle\Tests\Security;

use PHPUnit_Framework_TestCase;
use Ofertix\SecurityExtraBundle\Security\ControllerListener;
use Ofertix\SecurityExtraBundle\Annotation;
use Symfony\Component\HttpFoundation\Request;

/**
 * Class ControllerListenerTest
 */
class ControllerListenerTest extends PHPUnit_Framework_TestCase
{
    /**
     * This method acts as a Controller:Action stub for testing purposes
     */
    public function stubAction()
    {
    }

    /**
     *
     */
    public function test_exception_when_roles_are_needed_but_no_firewall_found()
    {
        $role = $this->getAnnotation('Role');
        $reader = $this->getAnnotationReader(array($role, ));
        $securityContext = $this->getSecurityContext();
        $event = $this->getControllerEvent();
        $controllerListener = new ControllerListener($reader, $securityContext);
        $this->setExpectedException('Symfony\Component\Security\Core\Exception\AuthenticationCredentialsNotFoundException');
        $controllerListener->onRole($event);
    }

    /**
     * @dataProvider provider_roles_granted
     */
    public function test_role_access(array $classAnnotations, array $methodAnnotations, array $contextConfig)
    {
        $reader = $this->getAnnotationReader($classAnnotations, $methodAnnotations);
        $securityContext = $this->getSecurityContext($contextConfig);
        $event = $this->getControllerEvent();
        $controllerListener = new ControllerListener($reader, $securityContext);
        $controllerListener->onRole($event);
    }

    public function provider_roles_granted()
    {
        $name = 'ROLE_USER';
        $annotation = $this->getAnnotation('Role', array(
            'getRoles' => array($name, ),
        ));

        $alternateName = 'ROLE_SUPER';
        $alternate = $this->getAnnotation('Role', array(
            'getRoles' => array($alternateName, ),
        ));

        $multiple = $this->getAnnotation('Role', array(
            'getRoles' => array($name, $alternateName, ),
        ));

        return $this->getAnnotationGrantedTestCases($annotation, $alternate, $multiple, $name, $alternateName);
    }

    /**
     * @dataProvider provider_roles_not_granted
     */
    public function test_role_denied(array $classAnnotations, array $methodAnnotations, array $contextConfig)
    {
        $reader = $this->getAnnotationReader($classAnnotations, $methodAnnotations);
        $securityContext = $this->getSecurityContext($contextConfig);
        $event = $this->getControllerEvent();
        $controllerListener = new ControllerListener($reader, $securityContext);
        $this->setExpectedException('Symfony\Component\Security\Core\Exception\AccessDeniedException');
        $controllerListener->onRole($event);
    }

    public function provider_roles_not_granted()
    {
        $name = 'ROLE_USER';
        $annotation = $this->getAnnotation('Role', array(
            'getRoles' => array($name, ),
        ));

        $alternateName = 'ROLE_SUPER';
        $alternate = $this->getAnnotation('Role', array(
            'getRoles' => array($alternateName, ),
        ));

        $multiple = $this->getAnnotation('Role', array(
            'getRoles' => array($name, $alternateName, ),
        ));

        return $this->getAnnotationNotGrantedTestCases($annotation, $alternate, $multiple, $name, $alternateName);
    }

    /**
     * @dataProvider provider_param_granted
     */
    public function test_param_access(array $classAnnotations, array $methodAnnotations, array $contextConfig)
    {
        $reader = $this->getAnnotationReader($classAnnotations, $methodAnnotations);
        $securityContext = $this->getSecurityContext($contextConfig);
        $event = $this->getControllerEvent();
        $this->addRequestToEvent($event);
        $controllerListener = new ControllerListener($reader, $securityContext);
        $controllerListener->onParam($event);
    }

    public function provider_param_granted()
    {
        $paramName = 'object';
        $name = 'ROLE_USER';
        $annotation = $this->getAnnotation('Param', array(
            'getName' => $paramName,
            'getRoles' => array($name, ),
        ));

        $alternateName = 'ROLE_SUPER';
        $alternate = $this->getAnnotation('Param', array(
            'getName' => $paramName,
            'getRoles' => array($alternateName, ),
        ));

        $multiple = $this->getAnnotation('Param', array(
            'getName' => $paramName,
            'getRoles' => array($name, $alternateName, ),
        ));

        $object = $this->getObject();
        return $this->getAnnotationGrantedTestCases($annotation, $alternate, $multiple, $name, $alternateName, $object);
    }

    /**
     * @dataProvider provider_param_not_granted
     */
    public function test_param_denied(array $classAnnotations, array $methodAnnotations, array $contextConfig)
    {
        $reader = $this->getAnnotationReader($classAnnotations, $methodAnnotations);
        $securityContext = $this->getSecurityContext($contextConfig);
        $event = $this->getControllerEvent();
        $this->addRequestToEvent($event);
        $controllerListener = new ControllerListener($reader, $securityContext);
        $this->setExpectedException('Symfony\Component\Security\Core\Exception\AccessDeniedException');
        $controllerListener->onParam($event);
    }

    public function provider_param_not_granted()
    {
        $paramName = 'object';
        $name = 'ROLE_USER';
        $annotation = $this->getAnnotation('Param', array(
            'getName' => $paramName,
            'getRoles' => array($name, ),
        ));

        $alternateName = 'ROLE_SUPER';
        $alternate = $this->getAnnotation('Param', array(
            'getName' => $paramName,
            'getRoles' => array($alternateName, ),
        ));

        $multiple = $this->getAnnotation('Param', array(
            'getName' => $paramName,
            'getRoles' => array($name, $alternateName, ),
        ));

        $object = $this->getObject();
        return $this->getAnnotationNotGrantedTestCases($annotation, $alternate, $multiple, $name, $alternateName, $object);
    }

    /**
     * Test cases for granted access
     */
    protected function getAnnotationGrantedTestCases($annotation, $alternate, $multiple, $name, $alternateName, $true = true)
    {
        return array(
            'a_class_annotation_is_needed_and_granted' => array(
                array($annotation, ),    // class annotations
                array(),                 // method annotations
                array($name => $true, ), // roles granted in context
            ),
            'many_class_annotations_are_needed_and_all_granted' => array(
                array($annotation, $alternate),
                array(),
                array($name => $true, $alternateName => $true, ),
            ),
            'a_class_multirole_is_needed_and_all_granted' => array(
                array($multiple, ),
                array(),
                array($name => $true, $alternateName => $true, ),
            ),
            'a_method_annotation_is_needed_and_granted' => array(
                array(),
                array($annotation, ),
                array($name => $true, ),
            ),
            'many_method_annotations_are_needed_and_all_granted' => array(
                array(),
                array($annotation, $alternate),
                array($name => $true, $alternateName => $true, ),
            ),
            'a_class_and_method_annotations_are_needed_and_all_granted' => array(
                array($annotation, ),
                array($alternate, ),
                array($name => $true, $alternateName => $true, ),
            ),
            'same_annotation_is_needed_in_class_and_method_and_granted' => array(
                array($annotation, ),
                array($annotation, ),
                array($name => $true, ),
            ),
        );
    }

    /**
     * Tests for denied access
     */
    protected function getAnnotationNotGrantedTestCases($annotation, $alternate, $multiple, $name, $alternateName, $true = true)
    {
        return array(
            'a_class_annotation_is_needed_but_not_granted' => array(
                array($annotation, ),    // class annotations
                array(),                 // method annotations
                array($name => false, ), // roles granted in context
            ),
            'many_class_annotations_are_needed_but_none_granted' => array(
                array($annotation, $alternate, ),
                array(),
                array($name => false, $alternateName => false, ),
            ),
            'a_class_multirole_is_needed_but_none_granted' => array(
                array($multiple, ),
                array(),
                array($name => false, $alternateName => false, ),
            ),
            'many_class_annotations_are_needed_but_only_one_granted' => array(
                array($annotation, $alternate, ),
                array(),
                array($name => $true, $alternateName => false, ),
            ),
            'a_class_multirole_is_needed_but_only_one_granted' => array(
                array($multiple, ),
                array(),
                array($name => $true, $alternateName => false, ),
            ),
            'a_method_annotation_is_needed_but_not_granted' => array(
                array(),
                array($annotation, ),
                array($name => false, ),
            ),
            'many_method_annotations_are_needed_but_none_granted' => array(
                array(),
                array($annotation, $alternate, ),
                array($name => false, $alternateName => false, ),
            ),
            'many_method_annotations_are_needed_but_only_one_granted' => array(
                array(),
                array($annotation, $alternate, ),
                array($name => $true, $alternateName => false, ),
            ),
            'a_class_and_method_annotations_are_needed_but_not_granted' => array(
                array($annotation, ),
                array($alternate, ),
                array($name => false, $alternateName => false, ),
            ),
            'a_class_and_method_annotations_are_needed_but_only_one_granted' => array(
                array($annotation, ),
                array($alternate, ),
                array($name => $true, $alternateName => false, ),
            ),
            'same_annotation_is_needed_in_class_and_method_but_not_granted' => array(
                array($annotation, ),
                array($annotation, ),
                array($name => false, ),
            ),
        );
    }

    /**
     * Returns an object to check @Param validation
     */
    protected function getObject()
    {
        static $object = null;
        if (null === $object) {
            $object = new \stdClass();
        }

        return $object;
    }

    /**
     * Mocks an Annotation
     */
    protected function getAnnotation($className, $methods = array())
    {
        $namespace = substr(__NAMESPACE__, 0, strpos(__NAMESPACE__, '\Tests\\')) . '\Annotation';
        $annotation = $this->getMock("{$namespace}\\{$className}", array_keys($methods), array(), '', false);
        foreach ($methods as $methodName => $value) {
            if (false === $value instanceof \PHPUnit_Framework_MockObject_Stub) {
                $value = $this->returnValue($value);
            }
            $annotation
                ->expects($this->any())
                ->method($methodName)
                ->will($value);
        }

        return $annotation;
    }

    /**
     * Mocks AnnotationReader with classAnnotations and methodAnnotations
     *
     * @param $classAnnotations
     * @param $methodAnnotations
     *
     * @return \Doctrine\Common\Annotations\AnnotationReader
     */
    protected function getAnnotationReader($classAnnotations = array(), $methodAnnotations = array())
    {
        $reader = $this->getMock('Doctrine\Common\Annotations\AnnotationReader');
        $reader
            ->expects($this->atLeastOnce())
            ->method('getClassAnnotations')
            ->will($this->returnValue($classAnnotations));
        $reader
            ->expects($this->atLeastOnce())
            ->method('getMethodAnnotations')
            ->will($this->returnValue($methodAnnotations));

        return $reader;
    }

    /**
     * @param array $roles
     *
     * @return \Symfony\Component\Security\Core\SecurityContextInterface
     */
    protected function getSecurityContext(array $roles = array())
    {
        $context = $this->getMock('Symfony\Component\Security\Core\SecurityContextInterface');
        $context
            ->expects($this->any())
            ->method('getToken')
            ->will($this->returnValue(empty($roles) ? false : true));

        $valueMap = array();
        foreach ($roles as $role => $value) {
            $param = is_bool($value) ? null : $value;
            $value = is_bool($value) ? $value : true;
            $valueMap[] = array($role, $param, $value);
        }

        $context
            ->expects($this->any())
            ->method('isGranted')
            ->will($this->returnValueMap($valueMap));

        return $context;
    }

    /**
     * Mocks FilterControllerEvent
     *
     * @return \Symfony\Component\HttpKernel\Event\FilterControllerEvent
     */
    protected function getControllerEvent()
    {
        $eventClass = 'Symfony\Component\HttpKernel\Event\FilterControllerEvent';
        $mockedMethods = array('getController');
        $eventBuilder = $this->getmockBuilder($eventClass, $mockedMethods);
        $eventBuilder->disableOriginalConstructor();
        $event = $eventBuilder->getMock();
        $event
            ->expects($this->any())
            ->method('getController')
            ->will($this->returnValue(
                array($this, 'stubAction')
            ));

        return $event;
    }

    protected function addRequestToEvent($event)
    {
        $request = new Request();
        $request->attributes->set('object', $this->getObject());
        /** @var \PHPUnit_Framework_MockObject_MockObject $event */
        $event
            ->expects($this->any())
            ->method('getRequest')
            ->will($this->returnValue($request));

        return $request;
    }
}
