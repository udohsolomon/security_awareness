# Improper Certificate Validation

## Description
Validation of X.509 certificates is essential to create secure SSL/TLS sessions not vulnerable to man-in-the-middle attacks.

The certificate chain validation includes these steps:

The certificate is issued by its parent Certificate Authority or the root CA trusted by the system.
* Each CA is allowed to issue certificates.
* Each certificate in the chain is not expired.
* It's not recommended to reinvent the wheel by implementing custom certificate chain validation.

TLS libraries provide built-in certificate validation functions that should be used.

## Vulnerable Code Example
There is no way to disable certificate verification in tls, https and request modules but it is possible to not reject request when verification fails.

https built-in module:
```java
let options = {
  hostname: 'www.example.com',
  port: 443,
  path: '/',
  method: 'GET',
  secureProtocol: 'TLSv1_2_method',
  rejectUnauthorized: false ; // Noncompliant
};

let req = https.request(options, (res) => {
  res.on('data', (d) => {
    process.stdout.write(d);
  });
}); // Noncompliant
```
tls built-in module:

```jave
let options = {
    secureProtocol: 'TLSv1_2_method',
    rejectUnauthorized: false ; // Noncompliant
};

let socket = tls.connect(443, "www.example.com", options, () => {
  process.stdin.pipe(socket);
  process.stdin.resume();
});  // Noncompliant
```
request module:

```java
let socket = request.get({
    url: 'www.example.com',
    secureProtocol: 'TLSv1_2_method',
    rejectUnauthorized: false ; // Noncompliant
});
```

## Mitigation
https built-in module:

```java
let options = {
  hostname: 'www.example.com',
  port: 443,
  path: '/',
  method: 'GET',
  secureProtocol: 'TLSv1_2_method'
};

let req = https.request(options, (res) => {
  res.on('data', (d) => {
    process.stdout.write(d);
  });
}); // Compliant: by default rejectUnauthorized  is set to true
```
tls built-in module:

```java
let options = {
    secureProtocol: 'TLSv1_2_method'
};

let socket = tls.connect(443, "www.example.com", options, () => {
  process.stdin.pipe(socket);
  process.stdin.resume();
}); // Compliant: by default rejectUnauthorized  is set to true
```
request module:

```java
let socket = request.get({
    url: 'https://www.example.com/',
    secureProtocol: 'TLSv1_2_method' // Compliant
}); // Compliant: by default rejectUnauthorized  is set to true
```


## Risk Assessment
Failure frequently compromises all data that should have been protected. Typically, this information includes sensitive personal information (PII) data such as health records, credentials, personal data, and credit cards, which often require protection as defined by laws or regulations such as the EU GDPR or local privacy laws.


## References
* [A3:2017-Sensitive Data Exposure]
* [A6:2017-Security Misconfiguration]


[A3:2017-Sensitive Data Exposure]:https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html
[A6:2017-Security Misconfiguration]:https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html

