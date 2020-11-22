# Cross-origin Communications Vulnerability

## Description
Browsers allow message exchanges between Window objects of different origins.

Because any window can send / receive messages from other window it is important to verify the sender's / receiver's identity:

* When sending message with postMessage method, the identity's receiver should be defined (the wildcard keyword (*) should not be used).
* When receiving message with message event, the sender's identity should be verified using the origin and possibly source properties.

## Vulnerabilities

When sending message:

```javascript
var iframe = document.getElementById("testiframe");
iframe.contentWindow.postMessage("secret", "*"); // Noncompliant: * is used
}
```

When receiving message:

```javascript
window.addEventListener("message", function(event) { // Noncompliant: no checks are done on the origin property.
      console.log(event.data);
 });
 ```


### Mitigation
When sending message:

```javascript
var iframe = document.getElementById("testsecureiframe");
iframe.contentWindow.postMessage("hello", "https://secure.example.com"); // Compliant
}
```
When receiving message:

```javascript
window.addEventListener("message", function(event) {

  if (event.origin !== "http://example.org") // Compliant
    return;

  console.log(event.data)
});
```
## Risk Assessment
Attackers have to gain access to only a few accounts, or just one admin account to compromise the system. Depending on the domain of the application, this may allow money laundering, social security fraud, and identity theft, or disclose legally protected highly sensitive information.

## References
* [OWASP Top 10 2017 Category A3 - Broken Authentication and Session Management]
* [Developer.mozilla.org - postMessage API]

[OWASP Top 10 2017 Category A3 - Broken Authentication and Session Management]:https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication
[Developer.mozilla.org - postMessage API]:https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage


