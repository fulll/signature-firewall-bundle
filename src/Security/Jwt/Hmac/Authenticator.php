<?php

namespace IED\SignatureFirewallBundle\Security\Jwt\Hmac;

use IED\SignatureFirewallBundle\Security\Jwt\AbstractAuthenticator;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Symfony\Component\Security\Core\User\UserInterface;

class Authenticator extends AbstractAuthenticator
{
    /**
     * {@inheritdoc}
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        $token     = $credentials['token'];
        $algorithm = new Sha256();

        if ($token->getHeader('alg') !== $algorithm->getAlgorithmId() || false === $token->verify($algorithm, $user->getPassword())) {
            return false;
        }

        return parent::checkCredentials($credentials, $user);
    }
}
