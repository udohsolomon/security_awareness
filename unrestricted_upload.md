# Unrestricted Upload of File

## Description
These minimum restrictions should be applied when handling file uploads:

* the file upload folder to restrict untrusted files to a specific folder.
* the file extension of the uploaded file to prevent remote code execution.
Also the size of the uploaded file should be limited to prevent denial of service attacks. 

## Vulnerable Code Example
### formidable module:

```javascript
const Formidable = require('formidable');

const form = new Formidable(); // Noncompliant, this form is not safe
form.uploadDir = ""; // because upload dir is not defined (by default os temp dir: /var/tmp or /tmp)
form.keepExtensions = true; // and file extensions are kept
```
### multer (Express.js middleware) module:

```javascript
const multer = require('multer');

let diskStorage = multer.diskStorage({ // Noncompliant: no destination specified
  filename: (req, file, cb) => {
    const buf = crypto.randomBytes(20);
    cb(null, buf.toString('hex'))
  }
```

## Mitigation
### formidable module:

```javascript
const Formidable = require('formidable');

const form = new Formidable(); // Compliant
form.uploadDir = "./uploads/";
form.keepExtensions = false;
```
### multer (Express.js middleware) module:

```javascript
const multer = require('multer');

let diskStorage = multer.diskStorage({  // Compliant
  filename: (req, file, cb) => {
    const buf = crypto.randomBytes(20);
    cb(null, buf.toString('hex'))
  },
  destination: (req, file, cb) => {
    cb(null, './uploads/')
  }
});

let diskupload = multer({
  storage: diskStorage,
});
```


## Risk Assessment
The impact of this vulnerability is high, supposed code can be executed in the server context or on the client side. The likelihood of detection for the attacker is high. The prevalence is common. As a result the severity of this type of vulnerability is high.
It is important to check a file upload module’s access controls to examine the risks properly.
Server-side attacks: The web server can be compromised by uploading and executing a web-shell which can run commands, browse system files, browse local resources, attack other servers, or exploit the local vulnerabilities, and so forth.


## References
* [CWE-434: Unrestricted Upload of File with Dangerous Type]
* [CWE-400: Uncontrolled Resource Consumption]
* [OWASP Top 10 2017 Category A4 - Insecure Direct Object References]
* [OWASP Unrestricted File Upload - Unrestricted File Upload]
* [CERT, IDS56-J. - Prevent arbitrary file upload]

[CWE-434: Unrestricted Upload of File with Dangerous Type]:https://cwe.mitre.org/data/definitions/434
[CWE-400: Uncontrolled Resource Consumption]:https://cwe.mitre.org/data/definitions/400.html
[OWASP Top 10 2017 Category A4 - Insecure Direct Object References]:https://owasp.org/www-project-top-ten/
[OWASP Unrestricted File Upload - Unrestricted File Upload]:https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
[CERT, IDS56-J. - Prevent arbitrary file upload]:https://wiki.sei.cmu.edu/confluence/display/java/IDS56-J.+Prevent+arbitrary+file+upload
