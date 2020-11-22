# Broken Authentication

## Description
Credentials should be stored outside of the code in a configuration file, a database or secret management service.

This rule flags instances of hard-coded credentials used in database and LDAP connections. It looks for hard-coded credentials in connection strings, and for variable names that match any of the patterns from the provided list.

It's recommended to customize the configuration of this rule with additional credential words such as "oauthToken", "secret", ...

Ask Yourself Whether
* Credentials allows access to a sensitive component like a database, a file storage, an API or a service.
* Credentials are used in production environments.
* Application re-distribution is required before updating the credentials.

There is a risk if you answered yes to any of those questions.

Recommended Secure Coding Practices
* Store the credentials in a configuration file that is not pushed to the code repository.
* Store the credentials in a database.
* Use the secret management service of you cloud provider.
* If the a password has been disclosed through the source code: change it.


## Vulnerable Code Example

```javascript
var mysql = require('mysql');

var connection = mysql.createConnection(
{
  host:'localhost',
  user: "admin",
  database: "project",
  password: "mypassword", // sensitive
  multipleStatements: true
});

connection.connect();
```


## Mitigation

```javascript
var mysql = require('mysql');

var connection = mysql.createConnection({
  host: process.env.MYSQL_URL,
  user: process.env.MYSQL_USERNAME,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE
});
connection.connect();
```

## Risk Assessment
Attackers have to gain access to only a few accounts, or just one admin account to compromise the system. Depending on the domain of the application, this may allow money laundering, social security fraud, and identity theft, or disclose legally protected highly sensitive information.


## References
* [A2:2017-Broken Authentication]
* [CWE-798: Use of Hard-coded Credentials]
* [CWE-259: Use of Hard-coded Password]



[A2:2017-Broken Authentication]:https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication.html
[CWE-798: Use of Hard-coded Credentials]:https://cwe.mitre.org/data/definitions/798
[CWE-259: Use of Hard-coded Password]:https://cwe.mitre.org/data/definitions/259


