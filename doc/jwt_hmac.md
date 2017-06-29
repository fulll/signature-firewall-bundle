JWT HMAC
=========================================

User provider has just to inherit from `Symfony\Component\Security\Core\User\UserInterface`, here is an example with a memory provider.
Password has to be available in clear text ... so be careful.

`security.yml`

```
ied_signature_firewall:
    firewalls:
        my_firewall:
            jwt:
                signer: hmac
                validation:
                    ttl:     100
                    request: [scheme, method, host, path_info, content, query_string]
```

Then:

```
security:
    providers:
        hmac_jwt_users:
            memory:
                users:
                    chuck: { password: norris, roles: ROLE_USER}
                    bruce: { password: lee, roles: ROLE_USER }

    firewalls:
        secured:
            pattern: /secured
            provider: jwt_rsa_provider
            guard:
                authenticators:
                    - ied.signature_firewall.authenticator.my_firewall
```
