<?php

namespace IED\SignatureFirewallBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use IED\SignatureFirewallBundle\Security\RequestSignatureValidator;

class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritDoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();

        $rootNode = $treeBuilder->root('ied_signature_firewall');
        $rootNode
            ->children()
                ->arrayNode('firewalls')
                    ->prototype('array')
                        ->children()
                            ->arrayNode('jwt')
                                ->addDefaultsIfNotSet()
                                ->children()
                                    ->enumNode('signer')->values(['rsa', 'hmac'])->end()
                                    ->arrayNode('validation')
                                        ->addDefaultsIfNotSet()
                                        ->children()
                                            ->integerNode('ttl')->defaultValue(null)->end()
                                            ->arrayNode('request')
                                                ->validate()
                                                    ->ifTrue(function($v) {
                                                        return count(array_diff($v, RequestSignatureValidator::getCriteria())) > 0 ? true : false;
                                                    })
                                                    ->thenInvalid(sprintf('Validation request expects values from: %s.', implode(', ', RequestSignatureValidator::getCriteria())))
                                                ->end()
                                                ->prototype('scalar')
                                            ->end()
                                        ->end()
                                    ->end()
                                ->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
