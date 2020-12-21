# Asymmetric Key Exchange

---

### Protocol

##### RSA
* **CVE-2018-12404**: A cached side channel attack during handshakes using RSA encryption could allow for the decryption of encrypted content. This is a variant of the Adaptive Chosen Ciphertext attack (AKA Bleichenbacher attack) and affects all NSS versions prior to NSS 3.41.
* **CVE-2017-1618**: On BIG-IP versions 11.6.0-11.6.2 (fixed in 11.6.2 HF1), 12.0.0-12.1.2 HF1 (fixed in 12.1.2 HF2), or 13.0.0-13.0.0 HF2 (fixed in 13.0.0 HF3) a virtual server configured with a Client SSL profile may be vulnerable to an Adaptive Chosen Ciphertext attack (AKA Bleichenbacher attack) against RSA, which when exploited, may result in plaintext recovery of encrypted messages and/or a Man-in-the-middle (MiTM) attack, despite the attacker not having gained access to the server's private key itself, aka a ROBOT attack.
* *[1998 CRYPTO]Chosen Ciphertext Attacks Against ProtocolsBased on the RSA Encryption Standard PKCS #1*
* *[2003 CHES]Attacking RSA-based Sessions in SSL/TLS*
* *[2014 USS]Revisiting SSL/TLS Implementations: New Bleichenbacher Side Channels and Attacks*
* *[2018 USS]Return Of Bleichenbacher’s Oracle Threat (ROBOT)*
* *[2019 SP]The 9 Lives of Bleichenbacher’s CAT:New Cache ATtacks on TLS Implementations*
#

##### Cross Protocol
* **CVE-2016-0800**: The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and other products, requires a server to send a ServerVerify message before establishing that a client possesses certain plaintext RSA data, which makes it easier for remote attackers to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding oracle, aka a "DROWN" attack.
* *[2013 CCS]A cross-protocol attack on the TLS protocol*
* *[2016 USS]DROWN: breaking tls using sslv2*
#

---

### Implementation

##### CCS Injection
* **CVE-2014-0224**: OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly restrict processing of ChangeCipherSpec messages, which allows man-in-the-middle attackers to trigger use of a zero-length master key in certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain sensitive information, via a crafted TLS handshake, aka the "CCS Injection" vulnerability.
#

##### Logjam
* **CVE-2015-4000**: The TLS protocol 1.2 and earlier, when a DHE_EXPORT ciphersuite is enabled on a server but not on a client, does not properly convey a DHE_EXPORT choice, which allows man-in-the-middle attackers to conduct cipher-downgrade attacks by rewriting a ClientHello with DHE replaced by DHE_EXPORT and then rewriting a ServerHello with DHE_EXPORT replaced by DHE, aka the "Logjam" issue.
* *[2015 CCS] Imperfect Forward Secrecy How Diffie-Hellman Fails in Practice*
#

##### ECDH
* *[2015 ESORICS]Practical Invalid Curve Attacks on TLS-ECDH*
#