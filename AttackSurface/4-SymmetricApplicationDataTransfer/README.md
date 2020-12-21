# Symmetric ApplicationData Transfer

---

### Compress

##### CRIME
* **CVE-2012-4929**: The TLS protocol 1.2 and earlier, as used in Mozilla Firefox, Google Chrome, Qt, and other products, can encrypt compressed data without properly obfuscating the length of the unencrypted data, which allows man-in-the-middle attackers to obtain plaintext HTTP headers by observing length differences during a series of guesses in which a string in an HTTP request potentially matches an unknown string in an HTTP header, aka a "CRIME" attack.
* *[2002 FSE]Compression and Information Leakage of Plaintext*
#

##### BREACH
* **CVE-2013-3587**: The HTTPS protocol, as used in unspecified web applications, can encrypt compressed data without properly obfuscating the length of the unencrypted data, which makes it easier for man-in-the-middle attackers to obtain plaintext secret values by observing length differences during a series of guesses in which a string in an HTTP request URL potentially matches an unknown string in an HTTP response body, aka a "BREACH" attack, a different issue than CVE-2012-4929.
* *[2013]BREACH: REVIVING THE CRIME ATTACK*
#

---

### Mode

##### CBC
* **CVE-2020-16150**: A Lucky 13 timing side channel in mbedtls_ssl_decrypt_buf in library/ssl_msg.c in Trusted Firmware Mbed TLS through 2.23.0 allows an attacker to recover secret key information. This affects CBC mode because of a computed time difference based on a padding length.
* **CVE-2014-3566**: The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other products, uses nondeterministic CBC padding, which makes it easier for man-in-the-middle attackers to obtain cleartext data via a padding-oracle attack, aka the "POODLE" issue.
* **CVE-2013-0169**: The TLS protocol 1.1 and 1.2 and the DTLS protocol 1.0 and 1.2, as used in OpenSSL, OpenJDK, PolarSSL, and other products, do not properly consider timing side-channel attacks on a MAC check requirement during the processing of malformed CBC padding, which allows remote attackers to conduct distinguishing attacks and plaintext-recovery attacks via statistical analysis of timing data for crafted packets, aka the "Lucky Thirteen" issue.
* **CVE-2011-3389**: The SSL protocol, as used in certain configurations in Microsoft Windows and Microsoft Internet Explorer, Mozilla Firefox, Google Chrome, Opera, and other products, encrypts data by using CBC mode with chained initialization vectors, which allows man-in-the-middle attackers to obtain plaintext HTTP headers via a blockwise chosen-boundary attack (BCBA) on an HTTPS session, in conjunction with JavaScript code that uses (1) the HTML5 WebSocket API, (2) the Java URLConnection API, or (3) the Silverlight WebClient API, aka a "BEAST" attack.
* *[2002 EUROCRYPT]Security Flaws Induced by CBC Padding Applications to SSL, IPSEC, WTLS...*
* *[2013 SP]Lucky Thirteen Breaking the TLS and DTLS Record Protocols*
* *[2014]This POODLE Bites: Exploiting The SSL 3.0 Fallback*

##### RC4
* **CVE-2013-2566**: The RC4 algorithm, as used in the TLS protocol and SSL protocol, has many single-byte biases, which makes it easier for remote attackers to conduct plaintext-recovery attacks via statistical analysis of ciphertext in a large number of sessions that use the same plaintext.
* *[2013 FSE]Full Plaintext Recovery Attack on Broadcast RC4*
#
