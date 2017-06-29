<?php

namespace IED\SignatureFirewallBundle\Security\Jwt;

use IED\SignatureFirewallBundle\Security\RequestSignatureValidator;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use Symfony\Component\HttpFoundation\Request;

class Validator
{
    private $ttl;
    private $requestSignatureValidator;

    const CLAIM_REQUEST_SIGNATURE = 'request_signature';

    public function __construct($ttl, RequestSignatureValidator $requestSignatureValidator = null)
    {
        $this->ttl = $ttl;
        $this->requestSignatureValidator = $requestSignatureValidator;
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

        if ($this->requestSignatureValidator) {
            if (false === $token->hasClaim(static::CLAIM_REQUEST_SIGNATURE)) {
                return false;
            }

            if (false === $this->requestSignatureValidator->validate($token->getClaim(static::CLAIM_REQUEST_SIGNATURE), $request)) {
                return false;
            }
        }

        return true;
    }
}
