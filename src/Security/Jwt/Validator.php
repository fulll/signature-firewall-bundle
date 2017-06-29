<?php

namespace IED\SignatureFirewallBundle\Security\Jwt;

use IED\SignatureFirewallBundle\Security\Signature\Config as SignatureConfig;
use IED\SignatureFirewallBundle\Security\Signature\Factory as SignatureFactory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use Symfony\Component\HttpFoundation\Request;

class Validator
{
    private $ttl;
    private $signatureConfig;

    const CLAIM_REQUEST_SIGNATURE = 'request_signature';

    public function __construct($ttl, SignatureConfig $signatureConfig = null)
    {
        $this->ttl = $ttl;
        $this->signatureConfig = $signatureConfig;
    }

    public function validate(Token $token, Request $request)
    {
        if (false === $token->validate(new ValidationData())) {
            return false;
        }


        if ($this->ttl) {
            if (false === $token->hasClaim('iat') || ($token->getClaim('iat') + $this->ttl) < time()) {
                return false;
            }
        }

        if ($this->signatureConfig) {
            if (false === $token->hasClaim(static::CLAIM_REQUEST_SIGNATURE)) {
                return false;
            }

            $signature = SignatureFactory::createFromSymfonyRequest($this->signatureConfig, $request);

            if ($signature != $token->getClaim(static::CLAIM_REQUEST_SIGNATURE)) {
                return false;
            }
        }

        return true;
    }
}
