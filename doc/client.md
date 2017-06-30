Client signature generation
===========================

Example with guzzle and Symfony:
--------------------------------

```
ied_signature_firewall:
    firewalls:
        my_firewall:
            jwt:
                signer: rsa
                validation:
                    ttl:     100
                    request: [scheme, method, host, path_info, content, query_string]
```


```php
<?php

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Psr7\Request as Psr7Request;
use IED\SignatureFirewallBundle\Security\Signature\Factor as SignatureFactory;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Keychain;
use Lcobucci\JWT\Signer\Rsa\Sha256;

$request = new Psr7Request('GET', 'http://myendpoint.loc/secured?foo=bar&bar=foo');

// Here you get the signature configuration for the `my_firewall` firewall.
$signatureConfig = $container->get('ied.signature_firewall.signature_config.my_firewall');
$signature = SignatureFactory::createFromPsr7Request($signatureConfig, $request);

$keychain = new Keychain();
$token = (new Builder())
    ->setIssuer('issuer')
    ->setIssuedAt(time())
    ->set('request_signature', $signature)
    ->sign(new Sha256(),  $keychain->getPrivateKey('file:///path/to/private/pem', 'passphrase'))
    ->getToken();

$request = $request->withHeader('Authorization', sprintf('bearer %s', $token));

$client = new HttpClient();
$client->send($request);
```
