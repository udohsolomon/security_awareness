# Weak SSL/TLS protocols 

## Description
Older versions of SSL/TLS protocol like "SSLv3" have been proven to be insecure.

This rule raises an issue when an SSL/TLS context is created with an insecure protocol version (ie: a protocol different from "TLSv1.2", "TLSv1.3", "DTLSv1.2" or "DTLSv1.3"). 

## Vulnerable Code Example
secureProtocol, minVersion/maxVersion and secureOptions should not be set to use weak TLS protocols (TLSv1.1 and lower):


```java
let options = {
  secureProtocol: 'TLSv1_method' // Noncompliant: TLS1.0 is insecure
};

let options = {
  minVersion: 'TLSv1.1',  // Noncompliant: TLS1.1 is insecure
  maxVersion: 'TLSv1.2'
};

let options = {
  secureOptions: constants.SSL_OP_NO_SSLv2 | constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_TLSv1
}; // Noncompliant TLS 1.1 (constants.SSL_OP_NO_TLSv1_1) is not disabled
```
### https built-in module:
```java
let req = https.request(options, (res) => {
  res.on('data', (d) => {
    process.stdout.write(d);
  });
});  // Noncompliant
```
### tls built-in module:
```java
let socket = tls.connect(443, "www.example.com", options, () => { });  // Noncompliant
```
### request module:

```java
let socket = request.get(options);
```


## Mitigation
Set either secureProtocol or secureOptions or minVersion to use secure protocols only (TLSv1.2 and higher):


```java
let options = {
  secureProtocol: 'TLSv1_2_method'
};
// or
let options = {
  secureOptions: constants.SSL_OP_NO_SSLv2 | constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_TLSv1 | constants.SSL_OP_NO_TLSv1_1
};
// or
let options = {
    minVersion: 'TLSv1.2'
};
```
### https built-in module:


```java
let req = https.request(options, (res) => {
  res.on('data', (d) => {
    process.stdout.write(d);
  });
});  // Compliant
```
### tls built-in module:

```java
let socket = tls.connect(443, "www.example.com", options, () => { });
```
### request module:

```java
let socket = request.get(options);
```

## Risk Assessment
The impact of this vulnerability is high, supposed code can be executed in the server context or on the client side. The likelihood of detection for the attacker is high. The prevalence is common. As a result the severity of this type of vulnerability is high.
It is important to check a file upload module’s access controls to examine the risks properly.
Server-side attacks: The web server can be compromised by uploading and executing a web-shell which can run commands, browse system files, browse local resources, attack other servers, or exploit the local vulnerabilities, and so forth.


## References
* [OWASP Top 10 2017 Category A3 - Sensitive Data Exposure]
* [OWASP Top 10 2017 Category A6 - Security Misconfiguration]
* [MITRE, CWE-327 - Inadequate Encryption Strength]
* [MITRE, CWE-326 - Use of a Broken or Risky Cryptographic Algorithm]
* [SSL and TLS Deployment Best Practices - Use secure protocols]

[OWASP Top 10 2017 Category A3 - Sensitive Data Exposure]:https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html
[OWASP Top 10 2017 Category A6 - Security Misconfiguration]:https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html
[MITRE, CWE-327 - Inadequate Encryption Strength]:https://cwe.mitre.org/data/definitions/326.html
[SSL and TLS Deployment Best Practices - Use secure protocols]:https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices#22-use-secure-protocols
[MITRE, CWE-326 - Use of a Broken or Risky Cryptographic Algorithm]:https://cwe.mitre.org/data/definitions/327.html
