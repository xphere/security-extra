<?php

namespace Ofertix\SecurityExtraBundle\ParamConverter;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\ConfigurationInterface;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\ParamConverter;
use Sensio\Bundle\FrameworkExtraBundle\Request\ParamConverter\ParamConverterInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\SecurityContext;

class UserParamConverter implements ParamConverterInterface
{
    /** @var SecurityContext */
    protected $securityContext;

    public function __construct(SecurityContext $securityContext)
    {
        $this->securityContext = $securityContext;
    }

    public function apply(Request $request, ConfigurationInterface $configuration)
    {
        /** @var $configuration ParamConverter */
        $user = $this->securityContext->getToken()->getUser();
        if ($user) {
            $request->attributes->set($configuration->getName(), $user);

            return true;
        }
    }

    public function supports(ConfigurationInterface $configuration)
    {
        return $configuration instanceof ParamConverter && $configuration->getName() === 'user';
    }
}
