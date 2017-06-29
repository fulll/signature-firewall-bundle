<?php

namespace IED\SignatureFirewallBundle\Security\Jwt\Rsa;

use IED\SignatureFirewallBundle\Security\Jwt\AbstractAuthenticator;
use IED\SignatureFirewallBundle\Security\Jwt\Rsa\UserRsaPublicKeyAwareInterface;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Symfony\Component\Security\Core\User\UserInterface;

class Authenticator extends AbstractAuthenticator
{
    /**
     * {@inheritdoc}
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        if (false === $user instanceof UserRsaPublicKeyAwareInterface) {
            return false;
        }

        $token     = $credentials['token'];
        $algorithm = new Sha256();

        if ($token->getHeader('alg') !== $algorithm->getAlgorithmId() || false === $token->verify($algorithm, $user->getRsaPublicKey())) {
            return false;
        }

        return parent::checkCredentials($credentials, $user);
    }
}
