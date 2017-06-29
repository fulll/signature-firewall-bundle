JWT RSA
=======

User provider has to inherit from `IED\SignatureFirewallBundle\Security\Jwt\Rsa\UserRsaPublicKeyAwareInterface`, and purpose a `getRsaPublicKey`

Example with a `App` entity like this:

```
<?php

namespace AppBundle\Entity;

use Symfony\Component\Security\Core\User\UserInterface;
use IED\SignatureFirewallBundle\Security\Jwt\Rsa\UserRsaPublicKeyAwareInterface;
use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Entity
 * @ORM\Table(name="app")
 */
class App implements UserInterface, UserRsaPublicKeyAwareInterface
{
    /**
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     * @ORM\Column(type="integer")
     */
    private $id;

    /**
     * @ORM\Column(type="string")
     */
    private $name;

    /**
     * @ORM\Column(type="text")
     */
    private $rsaPublicKey;

    public function getRsaPublicKey()
    {
        return $this->rsaPublicKey;
    }

    public function getUsername()
    {
        return $this->name;
    }

    public function getRoles()
    {
        return ['ROLE_USER'];
    }

    public function getPassword()
    {
    }

    public function getSalt()
    {
    }

    public function eraseCredentials()
    {
    }
}
```

`security.yml`

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

Then:

```
security:
    providers:
        jwt_rsa_provider:
            entity:
                class: AppBundle:App
                property: id
    firewalls:
        secured:
            pattern: /secured
            provider: jwt_rsa_provider
            guard:
                authenticators:
                    - ied.signature_firewall.authenticator.my_firewall
```
