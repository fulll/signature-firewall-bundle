<?php

namespace IED\SignatureFirewallBundle\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

class IEDSignatureFirewallExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container)
    {
        $config = $this->processConfiguration(new Configuration(), $configs);

        foreach ($config['firewalls'] as $id => $configuration) {
            // we have only jwt_rsa at this moment.
            $jwt = $configuration['jwt'];
            $validationData = $jwt['validation'];
            $requestSignatureValidator = ($validationData['request']) ? new Definition('IED\SignatureFirewallBundle\Security\RequestSignatureValidator', [$validationData['request']]) : null;
            $validator = new Definition('IED\SignatureFirewallBundle\Security\Jwt\Validator', [
                $validationData['ttl'],
                $requestSignatureValidator,
            ]);

            $authenticatorClass = ($jwt['signer'] === 'rsa') ? 'IED\SignatureFirewallBundle\Security\Jwt\Rsa\Authenticator' : 'IED\SignatureFirewallBundle\Security\Jwt\Hmac\Authenticator';

            $authenticator = new Definition($authenticatorClass, [$validator]);

            $container->setDefinition(sprintf('ied.signature_firewall.jwt_rsa_authenticator.%s', $id), $authenticator);
        }
    }
}
