<?php

namespace Ofertix\SecurityExtraBundle\Security;

use Doctrine\Common\Annotations\Reader;
use Ofertix\SecurityExtraBundle\Annotation;
use Symfony\Component\HttpKernel\Event\FilterControllerEvent;
use Symfony\Component\Security\Core\Exception;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Util\ClassUtils;

class ControllerListener
{
    private $annotationReader;
    private $securityContext;

    public function __construct(Reader $annotationReader, SecurityContextInterface $securityContext)
    {
      $this->annotationReader = $annotationReader;
      $this->securityContext = $securityContext;
    }

    public function onRole(FilterControllerEvent $event)
    {
        $annotations = $this->getAnnotations($event, function($annotation) {
            return $annotation instanceof Annotation\Role;
        });

        /** @var Annotation\Role[] $annotations */
        foreach ($annotations as $annotation) {
            foreach ($annotation->getRoles() as $role) {
                if (!$this->securityContext->isGranted($role)) {
                    throw new Exception\AccessDeniedException(sprintf(
                        'Role "%s" is not granted for current user.',
                        $role
                    ));
                }
            }
        }
    }

    public function onParam(FilterControllerEvent $event)
    {
        $annotations = $this->getAnnotations($event, function($annotation) {
            return $annotation instanceof Annotation\Param;
        });

        /** @var Annotation\Param[] $annotations */
        foreach ($annotations as $annotation) {
            $request = $event->getRequest();
            foreach ($annotation->getRoles() as $role) {
                $name = $annotation->getName();
                $param = $request->attributes->get($name);
                if (!$this->securityContext->isGranted($role, $param)) {
                    throw new Exception\AccessDeniedException(sprintf(
                        'Role "%s" is not granted for current user on parameter "%s"',
                        $role, $name
                    ));
                }
            }
        }
    }

    protected function getAnnotations(FilterControllerEvent $event, $filter)
    {
        $controller = $event->getController();
        list($object, $method) = $controller;
        $rc = new \ReflectionClass(ClassUtils::getRealClass($object));
        $rm = $rc->getMethod($method);

        $classAnnotations = $this->annotationReader->getClassAnnotations($rc);
        $methodAnnotations = $this->annotationReader->getMethodAnnotations($rm);
        $annotations = array_filter(array_merge($classAnnotations, $methodAnnotations), $filter);

        if (!empty($annotations) && !$this->securityContext->getToken()) {
            throw new Exception\AuthenticationCredentialsNotFoundException(sprintf(
                'Security annotation found outside firewall on "%s" in "%s"',
                $rm->getName(),
                $rc->getFileName()
            ));
        }

        return $annotations;
    }
}
