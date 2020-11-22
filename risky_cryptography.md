# Risky Cryptographic Algorithm

## Description
To perform secure cryptography, operation modes and padding scheme are essentials and should be used correctly according to the encryption algorithm:

* For block cipher encryption algorithms (like AES), the GCM (Galois Counter Mode) mode that works internally with zero/no padding scheme, is recommended. At the opposite, these modes and/or schemes are highly discouraged:
Electronic Codebook (ECB) mode is vulnerable because it doesn't provide serious message confidentiality: under a given key any given plaintext block always gets encrypted to the same ciphertext block.
Cipher Block Chaining (CBC) with PKCS#5 padding (or PKCS#7) is vulnerable to padding oracle attacks.
* RSA encryption algorithm should be used with the recommended padding scheme (OAEP)

## Vulnerable Code Example
crypto built-in module:
```javascript
crypto.createCipheriv("AES-128-CBC", key, iv); // Noncompliant: CBC with PKCS5/7 (set by default) is vulnerable to oracle padding attacks
crypto.createCipheriv("AES-128-ECB", key, ""); // Noncompliant: ECB doesn't provide serious message confidentiality
```

## Mitigation
crypto built-in module:
```javascript
crypto.createCipheriv("AES-256-GCM", key, iv);
```


## Risk Assessment
Such flaws frequently give attackers unauthorized access to some system data or functionality. Occasionally, such flaws result in a complete system compromise.
The business impact depends on the protection needs of the application and data.


## References
* [CWE-327: Use of a Broken or Risky Cryptographic Algorithm]
* [A6:2017-Security Misconfiguration]
* [CWE/SANS TOP 25 Most Dangerous Software Errors]



[CWE-327: Use of a Broken or Risky Cryptographic Algorithm]:https://owasp.org/www-project-top-ten/2017/A4_2017-XML_External_Entities_(XXE).html
[A6:2017-Security Misconfiguration]:https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.htmlXML_External_Entity_Prevention_Cheat_Sheet.html
[CWE/SANS TOP 25 Most Dangerous Software Errors]:https://www.sans.org/top25-software-errors/#cat3

