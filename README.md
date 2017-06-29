InExtenso Digital SignatureFirewallBundle
=========================================

Symfony firewall which handle signature security using Guard. 
JWT RSA & JWT HMAC supported only at this moment.

SignatureFirewallBundle use a token to identify user but it does more ...
It creates a signature from the request (see validation.request configuration). By this way, even if a malicious person steal the JWT token, he'll not be able to edit the request to use it. So If you generate only token with a short TTL, malicious person will only be able to launch the same request in a short range time.

Client has to know the request signature mechanism to generate the good token and that's all ...

Usage
=====

- [Client signature generation](doc/client.md)
- [JWT RSA](doc/jwt_rsa.md)
- [JWT HMAC](doc/jwt_hmac.md)
