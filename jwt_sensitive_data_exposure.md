# JWT Sensitive Data Exposure

## Description
If a JSON Web Token (JWT) is not signed with a strong cipher algorithm (or not signed at all) an attacker can forge it and impersonate user identities.

* Don't use none algorithm to sign or verify the validity of an algorithm.
* Don't use a token without verifying its signature before.

## Vulnerable Code Example
jsonwebtoken library:
```javascript
const jwt = require('jsonwebtoken');
let token = jwt.sign({ foo: 'bar' }, key, { algorithm: 'none' }); // Noncompliant: JWT should include a signature
jwt.verify(token, key, { expiresIn: 360000 * 5, algorithms: ['RS256', 'none'] }, callbackcheck); // Noncompliant: none algorithm should not be used when verifying JWT signature
```

## Mitigation
jsonwebtoken library:
```javascript
const jwt = require('jsonwebtoken');
let token = jwt.sign({ foo: 'bar' }, key, { algorithm: 'HS256' }); // Compliant
jwt.verify(token, key, { expiresIn: 360000 * 5, algorithms: ['HS256'] }, callbackcheck); // Compliant
```


## Risk Assessment
Failure frequently compromises all data that should have been protected. Typically, this information includes sensitive personal information (PII) data such as health records, credentials, personal data, and credit cards, which often require protection as defined by laws or regulations such as the EU GDPR or local privacy laws.


## References
* [A3:2017-Sensitive Data Exposure]
* [CWE-347: Improper Verification of Cryptographic Signature]


[A3:2017-Sensitive Data Exposure]:https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html
[CWE-347: Improper Verification of Cryptographic Signature]:https://cwe.mitre.org/data/definitions/347.html

