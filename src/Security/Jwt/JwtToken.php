<?php

namespace IED\SignatureFirewallBundle\Security\Jwt;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\Role\RoleInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Guard\Token\GuardTokenInterface;

class JwtToken extends AbstractToken implements GuardTokenInterface
{
    /**
     * @param UserInterface            $user  The user!
     * @param RoleInterface[]|string[] $roles An array of roles
     */
    public function __construct(UserInterface $user, $roles)
    {
        parent::__construct($roles);

        $this->setUser($user);

        parent::setAuthenticated(true);
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials()
    {
        return [];
    }
}
