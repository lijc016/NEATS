# Certificate Verify

---

### Certificate Validation

##### go to fail
* **CVE-2014-1266**: The SSLVerifySignedServerKeyExchange function in libsecurity_ssl/lib/sslKeyExchange.c in the Secure Transport feature in the Data Security component in Apple iOS 6.x before 6.1.6 and 7.x before 7.0.6, Apple TV 6.x before 6.0.2, and Apple OS X 10.9.x before 10.9.2 does not check the signature in a TLS Server Key Exchange message, which allows man-in-the-middle attackers to spoof SSL servers by (1) using an arbitrary private key for the signing step or (2) omitting the signing step.
#

##### Frankencerts
* **CVE-2014-1959**: lib/x509/verify.c in GnuTLS before 3.1.21 and 3.2.x before 3.2.11 treats version 1 X.509 certificates as intermediate CAs, which allows remote attackers to bypass intended restrictions by leveraging a X.509 V1 certificate from a trusted CA to issue new certificates.
* *[2014 SP]Using Frankencerts for Automated Adversarial Testing of Certificate Validation in SSL/TLS Implementations.*
#

---

### Certificate Authorizing

##### MD5 Collision
* **CVE-2004-2761**: The MD5 Message-Digest Algorithm is not collision resistant, which makes it easier for context-dependent attackers to conduct spoofing attacks, as demonstrated by attacks on the use of MD5 in the signature algorithm of an X.509 certificate.
#

##### DV Vulnerabilities
* "Ironically, the mechanism CAs use to issue certificates is itself vulnerable to man-in-the-middle attacks by network-level adversaries."
* *[2018 USS]Bamboozling Certificate Authorities with BGP*
* *[2018 NDSS]Cloud Strife: Mitigating the Security Risks of Domain-Validated Certificates*
* *[2018 SIGSAC]Domain Validation++ For MitM-Resilient PKI*
#

---

### Private Key Security

##### Heartbleed
* **CVE-2014-0160**: The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.
#

##### CDN & Private Key
* "Our study reveals various problems with the current HTTPS practice adopted by CDN providers, such as widespread use of invalid certificates, private key sharing, neglected revocation of stale certificates, and insecure back-end communication."
* *[2014 SP]When HTTPS Meets CDN A Case of Authentication in Delegated Service*
#

---

### Certificate Revocation
##### Ghost Domain
* **CVE-2012-1033**: The resolver in ISC BIND 9 through 9.8.1-P1 overwrites cached server names and TTL values in NS records during the processing of a response to an A record query, which allows remote attackers to trigger continued resolvability of revoked domain names via a "ghost domain names" attack.
* *[2012 NDSS]Ghost Domain Names: Revoked Yet Still Resolvable*
#