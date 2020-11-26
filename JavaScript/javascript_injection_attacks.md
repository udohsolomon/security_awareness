# JavaScript Injection Attacks

## Description

Injection attacks occur when a malicious user sends untrusted data to an interpreter as part of a parameter or query. This way, the attacker's malicious/hostile payload will execute unintended commands that the interpreter will perform, leading to access unauthorized access and leaking of sensitive information to unauthorized parties .

## 1. Server-Side JavaScript Injections (SSJI)

When running JavaScript code on the server-side (using languages such as Node.js for instance), an injection attack could lead to a full compromise of the application. Some well-known JavaScript functions are considered evil in the sense that they could allow an attacker to run arbitrary code or cause denial-of-service conditions, these functions are:
* eval()
* setTimeOut()
* setInterval(),
* Function()

## Vulnerable Code Example

Here is an example of a vulnerable code based on [this article](https://hydrasky.com/network-security/server-side-javascript-injection-ssjs/)

```node

var http = require('http');
http.createServer(function (request, response) {
  if (request.method === 'POST') {
    var data = '';
    request.addListener('data', 
        function(chunk) { 
            data += chunk; 
        });
    request.addListener('end', 
        function() {
            var requestData = eval("(" + data + ")");
            db.run(requestData.balance);
        });
  }
});
```
In this case, the eval function is invoked without performing any input validation on the data parameter. An attacker could send a value like this ```while(1);``` to cause a denial of service condition.

Another attack vector happens if the developer uses eval funcion to get parameter from the request in an scenario like this:

```node
var tax  = eval(req.body.tax);
var roth = eval(req.body.roth);
```
The attacker can now send arbitrary code that will be evaluated an executed in the back-end, take a look at this example:

```node
res.end(require('fs').readdirSync('.').toString());
```
This code will list all the files in the root directory, if a configuration file exposing secrets and database credentials resides in the root directory the attacker will be able to read the content by running this code:
```node
res.end(require('fs').readFileSync(filename))
```
Since the attacker can now server-side list directories, if configuration files are deployed she will be able to traverse them and get access to sensitive information.

## Mitigation

This type of injection attack can be prevented by performing a proper input data validation, and never trusting user's input.

Dangerous functions such as eval() should not be used when the input parameter comes from untrusted users, use a safer function such as JSON.parse() instead.
In this case, eval() function is not needed as the developer can do something like this:

``` node
var tax  = parseInt(req.body.tax);
```
Additionally, developers should be using the ``` use strict``` directive at the beginning of a function to enable [JavaScript strict mode](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Strict_mode)

# 2. SQL Injection attacks in JavaScript

Similar to other programming languages, when JavaScript code executes in the server-side and proper input data validation is not performed, it could lead to SQL Injection Attacks. 

As stated by OWASP, SQL Injection attacks occur when an attacker injects SQL statements via the input data from the client to the application to affect the execution of predefined SQL statements and commands.

[NPM (Node Package Manager) libraries](https://www.npmjs.com/advisories/1146) have found to be vulnerable to this type of flaws.

## Vulnerable Code Example

Snyk folks published a PoC for this attack, here is the vulnerable code they published:

```node
const Sequelize = require('./');
const sequelize = new Sequelize('mysql', 'root', 'root', {
  host: 'localhost',
  port: '3306',
  dialect: 'mariadb',
  logging: console.log,
});

class Project extends Sequelize.Model {}

Project.init({
        name: Sequelize.STRING,
        target: Sequelize.JSON,
    },
  {
        sequelize,
        tableName: 'projects',
});

(async () => {
  await sequelize.sync();

  console.log(await Project.findAll({
    where: {name: sequelize.json("target.id')) = 10 UNION SELECT VERSION(); -- ", 10)},
    attributes: ['name'],
    raw: true,
  }));
})();

```
As explained in the [advisory](https://snyk.io/vuln/SNYK-JS-SEQUELIZE-459751), sequelize.json() helper function not escaping values properly at formatting sub-paths for JSON queries for MySQL, MariaDB and SQLite.

## Mitigation

When using third-party libraries, make sure to review the security advisories available by third-parties, also it is important to do a risk assessment that can take into consideration the activity of the project, the security issues reported, and the fix ratio of defects.

All input must be properly escaped before it gets executed.

Use Place Holders whever possible:

```
connection.query("SELECT * FROM account_history WHERE account_owner= ? AND account_owner_dob = ? and account_number = ?",[
     req.body.account_owner,
     req.body.account_owner.dob,
     req.body.account_number
    ],function(error, account_history){
        //.. do more stuff here
    });

```

Named Place Holders can also be used:

```
connection.query("SELECT * FROM account_history WHERE account_owner = :account_owner AND account_owner_dob = :account_owner_dob and account_number = :account_number",[
     account_owner     : req.body.account_owner,
     account_owner.dob : req.body.account_owner.dob,
     account_number    : req.body.account_number
    ],function(error, account_history){
        //.. do more stuff here
    });

```

Veracode folks have a great article that covers this scenarios, please check it out [here](https://www.veracode.com/blog/secure-development/how-prevent-sql-injection-nodejs).

## References

[Snyk  SQL Injection Advisory](https://snyk.io/vuln/SNYK-JS-SEQUELIZE-459751)

[NPM SQL Injection Advisory](https://www.npmjs.com/advisories/1146)

[OWASP SQL Injection atttacks](https://owasp.org/www-community/attacks/SQL_Injection)

[JavaScript Strict mode](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Strict_mode)


