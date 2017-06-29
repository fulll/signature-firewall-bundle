<?php

namespace IED\SignatureFirewallBundle\Security\Jwt;

use IED\SignatureFirewallBundle\Security\Jwt\Validator;
use Lcobucci\JWT\Parser;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

abstract class AbstractAuthenticator extends AbstractGuardAuthenticator
{
    /** @var Validator */
    private $validator;

    const HEADER_PREFIX = 'bearer';

    /**
     * @param Validator $validator validator
     */
    public function __construct(Validator $validator)
    {
        $this->validator = $validator;
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials(Request $request)
    {
        if (!$token = $request->headers->get('Authorization')) {
            return;
        }

        $headerParts = explode(' ', $token);

        if (!(count($headerParts) === 2 && $headerParts[0] === static::HEADER_PREFIX)) {
            return;
        }

        try {
            $token = (new Parser())->parse($headerParts[1]);
        } catch (\InvalidArgumentException $e) {
            return;
        }

        return array(
            'request' => $request,
            'token'   => $token,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $token = $credentials['token'];

        if (false === array_key_exists('iss', $token->getClaims())) {
            return;
        }

        return $userProvider->loadUserByUsername($token->getClaims()['iss']->getValue());
    }

    /**
     * {@inheritdoc}
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        return $this->validator->validate($credentials['token'], $credentials['request']);
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        throw new AccessDeniedHttpException(strtr($exception->getMessageKey(), $exception->getMessageData()));
    }

    /**
     * {@inheritdoc}
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        throw new HttpException(Response::HTTP_UNAUTHORIZED);
    }

    /**
     * {@inheritdoc}
     */
    public function supportsRememberMe()
    {
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function createAuthenticatedToken(UserInterface $user, $providerKey)
    {
        return new JwtToken($user, $user->getRoles());
    }
}
