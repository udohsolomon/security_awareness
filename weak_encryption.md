# Weak Encryption

## Description
When generating cryptographic keys (or key pairs), it is important to use strong parameters. Key length, for instance, should provides enough entropy against brute-force attacks.

* For RSA and DSA algorithms key size should be at least 2048 bits long
* For ECC (elliptic curve cryptography) algorithms key size should be at least 224 bits long
* For RSA public key exponent should be at least 65537.

This rule raises an issue when an RSA, DSA or ECC key-pair generator is initialized using weak parameters.

It supports the following libraries:

* cryptography
* PyCrypto
* Cryptodome

## Vulnerable Code Example

```python
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

dsa.generate_private_key(key_size=1024, backend=backend) # Noncompliant
rsa.generate_private_key(public_exponent=999, key_size=2048, backend=backend) # Noncompliant
ec.generate_private_key(curve=ec.SECT163R2, backend=backend)  # Noncompliant
```


## Mitigation

```python
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

dsa.generate_private_key(key_size=2048, backend=backend) # Compliant
rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=backend) # Compliant
ec.generate_private_key(curve=ec.SECT409R1, backend=backend) # Compliant
```

## Risk Assessment
An attacker may be able to decrypt the data using brute force attacks. Such flaws frequently give attackers unauthorized access to some system data or functionality. Occasionally, such flaws result in a complete system compromise.


## References
* [CWE-326: Inadequate Encryption Strength]
* [A3:2017-Sensitive Data Exposure]
* [A6:2017-Security Misconfiguration]
* [NIST FIPS 186-4 - Digital Signature Standard (DSS)]



[CWE-326: Inadequate Encryption Strength]:https://cwe.mitre.org/data/definitions/326.html
[A3:2017-Sensitive Data Exposure]:https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html
[A6:2017-Security Misconfiguration]:https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html
[NIST FIPS 186-4 - Digital Signature Standard (DSS)]:https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
