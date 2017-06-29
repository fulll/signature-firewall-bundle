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

            $signatureConfig = null;
            if (!empty($validationData['request'])) {
                $signatureConfig = new Definition('IED\SignatureFirewallBundle\Security\Signature\Config', [$validationData['request']]);
                $container->setDefinition(sprintf('ied.signature_firewall.signature_config.%s', $id), $signatureConfig);
            }

            //$signatureConfig = ($validationData['request']) ? new Definition('IED\SignatureFirewallBundle\Security\Signature\Config', [$validationData['request']]) : null;
            $validator = new Definition('IED\SignatureFirewallBundle\Security\Jwt\Validator', [
                $validationData['ttl'],
                $signatureConfig
            ]);

            $authenticatorClass = ($jwt['signer'] === 'rsa') ? 'IED\SignatureFirewallBundle\Security\Jwt\Rsa\Authenticator' : 'IED\SignatureFirewallBundle\Security\Jwt\Hmac\Authenticator';

            $authenticator = new Definition($authenticatorClass, [$validator]);

            $container->setDefinition(sprintf('ied.signature_firewall.authenticator.%s', $id), $authenticator);
        }
    }
}
