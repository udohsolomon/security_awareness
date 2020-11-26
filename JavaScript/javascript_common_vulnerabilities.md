# Common Vulnerabilities in JavaScript code

JavaScript vulnerabilities can be classified in two groups: those targeting the front-end layer (by exploiting client-side vulnerabilities such as Cross-Site Scripting or XSS for short) and with the advent of JavaScript in the back-end, there are new opportunities to compromise applications by exploiting a new set of vulnerabilities such as remote code execution.


## Cross-Site Scripting

XSS attacks are one of the most prevalent security flaws and mainly they occur when an application includes user-supplied data that is sent to the browser without proper input data validation or sanitization.

There are three types of XSS flaws:
* Stored
* Reflected
* DOM-based XSS attacks

For a deep understanding on the risks associated to XSS from JavaScript, please refer to [[Security] OWASP Top 10 for JavaScript - A2: Cross-Site Scripting - XSS](https://erlend.oftedal.no/blog/static-127.html).


# Code examples

Let's assume that we have a Web application that writes down in a div, the data that came from a text form or dropdown list that the user selected:

```html
<div class="data"/>
````

Here is the JavaScript code:

```JavaScript
var input = $("txtCommend").val();
$('.data').html(input);

// If the user sends this payload:
// '<script>alert("XSS");</script\>'
// It will evaluate the this code, 

```

## Source Code Vulnerabilities

With the rapid growth of packages or libraries in the registry (such as npm), injecting vulnerabilities into open-source packages becomes a low-hanging fruit for attackers, because that code can allow them to execute arbitrary code , spread malware, and exfiltrate secrets and sensible information.

Therefore when relying on a third-party, open-source library risk assessment is a key player that needs to be considered.

## Stealing Sensitive Data

JavaScript can be used to steal session identifiers of the current logged in user and post that information to a user's controlled domain; if proper session expiration is not in place, an attacker will be able to access the user session and perform actions on his behalf.

To avoid this type of issues, session attributes such as Http-Only needs to be implemented Web browsers are instructed to not allow JavaScript code (client-side code) to read the cookies from the DOM.

# References

[[Security] OWASP Top 10 for JavaScript - A2: Cross Site Scripting - XSS](https://erlend.oftedal.no/blog/static-127.html)

[JavaScript Security](https://www.veracode.com/security/javascript-security)

[Cross Site Scripting](https://owasp.org/www-community/attacks/xss/)
