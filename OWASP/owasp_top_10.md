# The OWASP Top 10

## Description

The Open Web Application Security Project or OWASP for short, is a global, non-profit organization, focused on making Web Application Security visible. Thousands of volunteers donate hours of their time providing guidelines, documentation, and tools to help developers to write secure applications.

OWASP provides an unlimited set of resources for developers, including the so-called OWASP Top 10, which is a standard awareness document for developers and Web Application Security. The current OWASP Top 10 version is the OWASP Top 10 2017 whose official documentation can be found [here](https://owasp.org/www-project-top-ten/2017/).

Developers are required to have a good understanding of this standard in a way they can write secure code. Once the OWASP Top 10 has been mastered, is recommended that developers continue to understand security risks; as the current threat landscape continues to evolve, threat actors will find creative and novel ways to compromise applications.

Here is a quick summary of the most critical Web Application Security Risks.

## A1 - Injection Attacks

As its name implies, an Injection Attack happens when an application fails to perform a correct input data validation (input data is not validated, filtered or sanitized by the application), allowing a threat actor to send arbitrary or hostile data to the server. There are multiple attack vectors related to Injection Attacks, such as:

* SQL Injection
* LDAP Injection
* XPath Injection 
* NoSQL Injection.

One of the most prevalent Injection Attacks is SQL Injection, since most transactional Web Applications require some mechanism to persist data, if proper input handling is not performed, an attacker can exploit this vulnerability.

Let's suppose the Online Banking Application receives a bank account identifier and should return all the transacctions for that account in a given interval:

```sql
var sql = "SELECT * FROM account_history WHERE
accountID='" + request.getParameter("accountID") + "'

```
The above code is vulnerable because the attacker could craft a payload like this:

```
https://www.supersecurebank.com/account-history?accountID=' or '1'='1

```
In this case, the application will return all the account history for all the accounts in the database, leaking confidential information to non-authorized parties.

### Recommendations

OWASP provides these recommendations:

The preferred option is to use a safe API, which avoids the use of the interpreter entirely or provides a parameterized interface, or migrate to use Object Relational Mapping Tools (ORMs)

*Note: Even when parameterized, stored procedures can still introduce SQL injection if PL/SQL or T-SQL concatenates queries and data, or executes hostile data with EXECUTE MMEDIATE or exec().*

* Use positive or "whitelist" server-side input validation. This is not a complete defense as many applications require special characters, such as text areas or APIs for mobile applications.
* For any residual dynamic queries, escape special characters using the specific escape syntax for that interpreter.
Note: SQL structures such as table names, column names, and so on cannot be escaped, and thus user-supplied structure names are dangerous. This is a common issue in report-writing software.
* Use LIMIT and other SQL controls within queries to prevent mass disclosure of records in case of SQL injection.
  

## A2 - Broken Authentication

This security risk involves the incorrect implementation of authentication-related activities such as session management, allowing a malicious actor to steal session identifiers and tokens or other implementation flaws that allow an attacker to impersonate a legitimate user within the system or application.

The following code represents a session management security issue

```node
function addUser(){
    var user = {
    userName  : userName,
    firstName : firstName,
    lastName  : lastName,
    password  : password  

    this.persistUserData(user, callback)({
        // do other stuff
    });
};

}
```
As you can see, the password is a plain text value that is being persisted in a database. Standard security practices encourage developers to implement robust mechanisms to store passwords in a database by implementing salt hashing using cryptographic secure hashing algorithms such as bcrypt.

### Recommendations

* Implement multi-factor authentication when is possible.
* Do not deploy software with default admin credentials
* Follow a good standard for Password Security such as [NIST 800-63 B's guidelines in section 5.1.1 for Memorized Secrets](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret)
* Never store passwords in clear text, always implement hashing with salt.
* Limit or increasingly delay failed login attempts. Log all failures and alert administrators when credential stuffing, brute force, or other attacks are detected

## A3 - Sensitive Data Exposure

Attackers commonly attempt to gain access to sensitive information and a mechanism to achieve this is to exploit vulnerabilities by executing man-in-the-middle attacks to steal credentials being transmitted in clear text.

Encrypting sensitive data is key to protect it from unauthorized access and tampering but is also important that proper key management is implemented.

Sensitive data exposure also occurs when the developers hardcodes tokens, secrets, api keys or passwords within the source code of the application or when sensitive data is being logged in server logs.

### Recommendations
OWASP Provides the following recommendations:

* Classify data processed, stored, or transmitted by an
application. Identify which data is sensitive according to privacy laws, regulatory requirements, or business needs.
* Don’t store sensitive data unnecessarily. Discard it as soon as possible or use PCI DSS compliant tokenization or even truncation. Data that is not retained cannot be stolen.
* Make sure to encrypt all sensitive data at rest.
* Ensure up-to-date and strong standard algorithms, protocols, and keys are in place; use proper key management.
* Encrypt all data in transit with secure protocols such as TLS with perfect forward secrecy (PFS) ciphers, cipher prioritization by the server, and secure parameters. Enforce encryption using directives like HTTP Strict Transport Security (HSTS).
* Disable caching for responses that contain sensitive data.
* Store passwords using strong adaptive and salted hashing functions with a work factor (delay factor), such as Argon2, scrypt, bcrypt, or PBKDF2.

## A4 - XML External Entities(XXE)

A threat actor could exploit this vulnerability if the Web application process XML documents and contains a XML processor that allows arbitrary XML content to be executed, by injecting hostile code within the definition of an external entity, an attacker could execute remote code and extract data.

Examples of this vulnerability:

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM  "file:///dev/random" >]>
<foo>&xxe;</foo>
```

And remote code execution:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo
  [<!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM "expect://id" >]>
<creds>
  <user>`&xxe;`</user>
  <pass>`mypass`</pass>
</creds>
```


These type of vulnerabilities usually have a significant impact and therefore they are classified as critical. Here are some examples of some disclosed vulnerabilities and it's impact.

* [CVE-2020-25257]https://nvd.nist.gov/vuln/detail/CVE-2020-25257
* [CVE-2019-9670 Detail]https://nvd.nist.gov/vuln/detail/CVE-2019-9670


### Recommendations

OWASP provides a great article titled [ML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) with good recommendations on how to prevent this attack from happening.

## A5 - Broken Access Control

This security risk involves flaws on access control mechanisms (also known as authorization). Access controls are necessary to verify the actions an authenticated user can do within the system. Access controls are difficult to implement securely specifically because the application could implement a specific set of groups and roles.

Access control must be centralized; if a new feature is added to the application, it will inherit the current access controls implemented avoiding that new features are deployed insecurely.

Sometimes Access Control is very granular and developers overlook them. As depicted be
```node
// URL to get the loan detail
GET https://securebankingapplication.com/api/loans/1000/details

app.get('/api/loans/:loanid/details', function(req, res) {
  // getting the loan identifier from the URI
  var loanID = req.params.loanid;
  // perform a database lookup

  db.getLoan(loanId, function(){
    // do more stuff here
  })
  
});

```
The problem with this code is that it does not perform an access control check to determine if the loan being requested belongs to the authenticated user (or is authorized based on business rules).

Even worse if the loan identifier is a predictable value (a consecutive number or a predictable composed value), the malicious actor could enumerate a large number of loans.

### Recomendations

OWASP provides the following recommendations to address this flaw:
Access control is only effective if enforced in trusted server-side code or server-less API, where the attacker cannot modify the access control check or metadata.
* With the exception of public resources, deny by default.
* Implement access control mechanisms once and re-use them throughout the application, including minimizing CORS usage.
* Model access controls should enforce record ownership, rather than accepting that the user can create, read, update, or delete any record.
* Unique application business limit requirements should be enforced by domain models.
* Disable web server directory listing and ensure file metadata (e.g. .git) and backup files are not present within web roots.
* Log access control failures, alert admins when appropriate (e.g. repeated failures).
* Rate limit API and controller access to minimize the harm from automated attack tooling.
* JWT tokens should be invalidated on the server after logout.
Developers and QA staff should include functional access control unit and integration tests.

## A6 - Security Misconfiguration

There is a well-known dilemma between defenders (all the team involved in creating an application and ensuring it is secure and reliable from development to deployment) and attackers (threat actors abusing the application) and it relies on the fact that defenders must be always vigilant, making sure all the infrastructure and  application are secure, that patches are deployed, that security defenses are in a good health and that periodically security assessments are performed. The attacker, in the other hand, just needs to find a security misconfiguration to compromise the application and the organization.

Therefore, attackers will exploit unpatched flaws, unused files or directories, unused pages and any other misconfiguration to gain unauthorized access to the systems.

Some examples of security misconfigurations are:

* Default credentials that are deployed to production
* Unpatched operating system
* Exposed configuration files (leaking secrets and tokens to unauthorized parties)
* Open ports and weak credentials that can be enumerated and brute-forced by a threat actor.

### Recommendations

When building an application all the components (host, application and network) must have the same level of security in place. A repeatable hardening process that is easier to deploy and manage must be implemented.
Environments (development, staging, production) must be isolated.
A segmented application architecture that provides effective and secure separation between components or tenants, with segmentation, containerization, or cloud security groups (ACLs).

## A7- Cross-Site Scripting (XSS)

XSS attacks happen when a malicious user sends hostile data to a Web application without proper input data validation and sanitization.
Typically there are three types of XSS flaws:
* Reflected XSS: User's untrusted data is sent as part of a HTML output, allowing an attacker to execute arbitrary JavaScript code in the user's browser.
* Stored XSS: The application stores user's data without performing any sort of validation, sanitization or escaping; later another user will access the data and the payload will be rendered, stealing sensitive information, redirecting the user to an attacker's controlled domain.
* DOM-based XSS: JavaScript frameworks, single-page applications, and APIs that dynamically include attacker-controllable data to a page are vulnerable to DOM XSS. Ideally, the application would not send attacker-controllable data to unsafe JavaScript APIs.

XSS flaws are very prevalent and can be found on multiple places, here is an example of this vulnerability on a network security vendor [CVE-2020-2036 PAN-OS: Reflected Cross-Site Scripting (XSS) vulnerability in management web interface](https://security.paloaltonetworks.com/CVE-2020-2036)

### Recommendations

OWASP security best practices recommends:

* Using frameworks that automatically escape XSS by design, such as the latest Ruby on Rails, React JS. Learn the limitations of each framework’s XSS protection and appropriately handle the use cases which are not covered.
* Escaping untrusted HTTP request data based on the context in the HTML output (body, attribute, JavaScript, CSS, or URL) will resolve Reflected and Stored XSS vulnerabilities. The OWASP Cheat Sheet 'XSS Prevention' has details on the required data escaping techniques.
* Applying context-sensitive encoding when modifying the browser document on the client side acts against DOM XSS. When this cannot be avoided, similar context sensitive escaping techniques can be applied to browser APIs as described in the OWASP Cheat Sheet ‘DOM based XSS Prevention’.
* Enabling a Content Security Policy (CSP) as a defense-in-depth mitigating control against XSS. It is effective if no other vulnerabilities exist that would allow placing malicious code via local file includes (e.g. path traversal overwrites or vulnerable libraries from permitted content delivery networks).

## A8 - Insecure Deserialization

Deserialization can be defined as the process to transform an object into a format that can be restored eventually, this is a common approach when objects are stored or to send them in a communication channel. A common use case is to convert an object to a JSON representation. 

The most common serialization formats are XML and JSON (or native serialization alternatives provided by the programming languages).

However, malicious actors could manipulate the serialization data to attempt to execute remote code (RCE), allow denial-of-service or abuse from access controls.

As an example, the node-serialize npm package is vulnerable to Arbitrary Code Execution when untrusted user-input is passed into the unserialize() function (https://snyk.io/vuln/npm:node-serialize:20170208)

### Remediation

As recommended by [OWASP](https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization), the only safe architectural pattern is not to accept serialized objects from untrusted sources or to use serialization mediums that only permit primitive data types.

Aditional controls are recommended by [OWASP](https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization):

* Implementing integrity checks such as digital signatures on any serialized objects to prevent hostile object creation or data tampering.
* Enforcing strict type constraints during deserialization before object creation as the code typically expects a definable set of classes. Bypasses to this technique have been demonstrated, so reliance solely on this is not advisable.
* Isolating and running code that deserializes in low privilege environments when possible.
* Log deserialization exceptions and failures, such as where the incoming type is not the expected type, or the deserialization throws exceptions.
* Restricting or monitoring incoming and outgoing network connectivity from containers or servers that deserialize.
* Monitoring deserialization, alerting if a user deserializes constantly.

## A9 - Using Components with Known Vulnerabilities

The current Software Development ecosystem promotes the creation of libraries that can be shared to the community, some of those ecosystems are The Node Package Management registry (npm), The Python Package Index (pypi), Maven Repository, NuGet package management for .NET among others.

From a security standpoint, when relying on third party libraries, it is required to perform a security assestment and determine well-maintained the library is, how many security issues has been reported, what is the bug fixing ratio. Aditionally, it is recommended to perform a security code review to determine if the library is not arbitrarily exfiltrating data to an attacker's controlled domain or if it does not exposes a security backdoor.

Multiple libraries have found vulnerable and by adding them to our projects, indirectly we are adding security risks.

Adding a library that has been modified by a threat actor could lead to exposure of sensitive information, arbitrary code execution, backdoors and multiple other risks affecting the organization.

### Recommendations
* Always keep an inventory of the third party libraries (and versions) being used across multiple projects.
* Perform a security code review on the source code of the application before using it.
* Keep the libraries up to date, visit public available vulnerability advisories.
* Use packages and libraries from official sources.


## A10 - Insufficient  Logging and Monitoring

When dealing with a security incident, logs are very valued resource because can help to understand how the attacker abused from an application. When an application is deployed to the internet, threat actors will interact with it and will attempt exploit vulnerabilities that allows them to gain unauthorized access.

Active monitoring is a mechanims to identify attackers in the initial stages. Proper logging and continious monitoring is key to detect attacks.

Logs can help us to understand how external entities interact with the application, what kind of vulnerabilities are trying to exploit, from where the traffic is coming from, if attackers are actively scanning our application and infraestructure and if brute-force attacks are happening among other questions of interests.

### Recommendations

It is recommended to implement a logging strategy that allows investigators and developers to do troubleshooting in the event an attack happens. 
Monitoring accounts activity is key; actions such as account creation, passwords resets, access control failures needs to be logged and monitored to identify a suspicious activity happening.
Logs centralization is recommended as threat actors will attempt to hide their activities by clearing logs upon performing their activities.
Add extra layer of security on top of the Web Applications by implementing Web Appplication Firewalls (either commercial or Open Source).

## References
* Dafydd, S. Pinto M. The Web Application Hacker's Handbook 2nd Edition
* McGraw, G. Hoglund, G. Exploiting Software - How to break code
* McGraw, G. Software Security - Building Security In.
* [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
* [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
* [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* [Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
* [Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
  


