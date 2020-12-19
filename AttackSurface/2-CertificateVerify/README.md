# Certificate Verify

---

### Certificate Validation

##### go to fail:
* **CVE-2015-1226**: The DebuggerFunction::InitAgentHost function in browser/extensions/api/debugger/debugger_api.cc in Google Chrome before 41.0.2272.76 does not properly restrict what URLs are available as debugger targets, which allows remote attackers to bypass intended access restrictions via a crafted extension.
#

##### Frankencerts
* **CVE-2014-1959**: lib/x509/verify.c in GnuTLS before 3.1.21 and 3.2.x before 3.2.11 treats version 1 X.509 certificates as intermediate CAs, which allows remote attackers to bypass intended restrictions by leveraging a X.509 V1 certificate from a trusted CA to issue new certificates.
* *[2014 SP]Using Frankencerts for Automated Adversarial Testing of Certificate Validation in SSL/TLS Implementations.*

---

### Certificate Authorizing

##### MD5 collision
* **CVE-2004-2761**: The MD5 Message-Digest Algorithm is not collision resistant, which makes it easier for context-dependent attackers to conduct spoofing attacks, as demonstrated by attacks on the use of MD5 in the signature algorithm of an X.509 certificate.
#

##### Miss

---

### Private Key Security

---

### Certificate Revocation