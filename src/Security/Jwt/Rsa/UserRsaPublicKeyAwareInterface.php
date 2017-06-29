<?php

namespace IED\SignatureFirewallBundle\Security\Jwt\Rsa;

/**
 * UserRsaPublicKeyAwareInterface
 *
 * @author Stephane PY <s.py@xeonys.com>
 */
interface UserRsaPublicKeyAwareInterface
{
    /**
     * {@inheritdoc}
     */
    public function getRsaPublicKey();
}
