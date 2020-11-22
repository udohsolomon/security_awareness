# Cross-Site Request Forgery (CSRF)

## Description
Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they’re currently authenticated. With a little help of social engineering (such as sending a link via email or chat), an attacker may trick the users of a web application into executing actions of the attacker’s choosing. If the victim is a normal user, a successful CSRF attack can force the user to perform state changing requests like transferring funds, changing their email address, and so forth. If the victim is an administrative account, CSRF can compromise the entire web application.

CSRF vulnerabilities occur when attackers can trick a user to perform sensitive authenticated operations on a web application without his consent.

Ask Yourself Whether
* There exist sensitive operations on the web application that can be performed when the user is authenticated.
* The state / resources of the web application could be modified by doing HTTP POST or HTTP DELETE requests for example.
* The web application is not only a public API designed to be requested by external websites.

There is a risk if you answered yes to any of those questions.

Recommended Secure Coding Practices
* Protection against CSRF attacks is strongly recommended:
** to be activated by default for all unsafe HTTP methods.
** implemented, for example, with an unguessable CSRF token
* Of course all sensitive operations should not be performed with safe HTTP methods like GET which are designed to be used only for information retrieval.

## Vulnerable Code Example
Express.js CSURF middleware protection is not found on an unsafe HTTP method like POST method:

```javascript
let csrf = require('csurf');
let express = require('express');

let csrfProtection = csrf({ cookie: true });

let app = express();

// Sensitive: this operation doesn't look like protected by CSURF middleware (csrfProtection is not used)
app.post('/money_transfer', parseForm, function (req, res) {
  res.send('Money transferred');
});
```
Protection provided by Express.js CSURF middleware is globally disabled on unsafe methods:


## Mitigation
Express.js CSURF middleware protection is used on unsafe methods:


```javascript
let csrf = require('csurf');
let express = require('express');

let csrfProtection = csrf({ cookie:  true });

let app = express();

app.post('/money_transfer', parseForm, csrfProtection, function (req, res) { // Compliant
  res.send('Money transferred')
});
```
Protection provided by Express.js CSURF middleware is enabled on unsafe methods:


## Risk Assessment
Such flaws frequently give attackers unauthorized access to some system data or functionality. Occasionally, such flaws result in a complete system compromise. The business impact depends on the protection needs of the application and data.


## References
* [CWE-352: Cross-Site Request Forgery (CSRF)]
* [Cross Site Request Forgery (CSRF)]
* [CWE/SANS TOP 25 Most Dangerous Software Errors]
* [A6:2017-Security Misconfiguration]



[CWE-352: Cross-Site Request Forgery (CSRF)]:https://cwe.mitre.org/data/definitions/352.html
[Cross Site Request Forgery (CSRF)]:https://owasp.org/www-community/attacks/csrf
[CWE/SANS TOP 25 Most Dangerous Software Errors]:https://www.sans.org/top25-software-errors/#cat1
[A6:2017-Security Misconfiguration]:https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html


