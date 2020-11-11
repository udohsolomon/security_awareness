# Database Injection Attacks

## Description
User provided data, such as URL parameters, should always be considered untrusted and tainted. Constructing SQL or SQL-like queries directly from tainted data enables attackers to inject specially crafted values that change the initial meaning of the query itself. Successful database query injection attacks can read, modify, or delete sensitive information from the database and sometimes even shut it down or execute arbitrary operating system commands.

Typically, the solution is to rely on prepared statements rather than string concatenation, which ensures that user provided data will be properly escaped. Also, the use of database ORMs is generally safe as most implementations rely on prepared statements.

An other solution is to validate every parameter used to build the query. This can be achieved by transforming string values to primitive types or by validating them against a white list of accepted values.

This rule supports: sqlite3, mysql, pymysql, psycopg2, pgdb, Django ORM and Flask-SQLAlchemy.

## Vulnerable Code Example
* Flask application

```python
from flask import request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from database.users import User

@app.route('hello')
def hello():
    id = request.args.get("id")
    stmt = text("SELECT * FROM users where id=%s" % id) # Query is constructed based on user inputs
    query = SQLAlchemy().session.query(User).from_statement(stmt) # Noncompliant
    user = query.one()
    return "Hello %s" % user.username
```
* Django application

```python
from django.http import HttpResponse
from django.db import connection

def hello(request):
    id = request.GET.get("id", "")
    cursor = connection.cursor()
    cursor.execute("SELECT username FROM auth_user WHERE id=%s" % id) # Noncompliant; Query is constructed based on user inputs
    row = cursor.fetchone()
    return HttpResponse("Hello %s" % row[0])
```

## Mitigation
* Flask application

```python
from flask import request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from database.users import User

@app.route('hello')
def hello():
    id = request.args.get("id")
    stmt = text("SELECT * FROM users where id=:id")
    query = SQLAlchemy().session.query(User).from_statement(stmt).params(id=id) # Compliant
    user = query.one()
    return "Hello %s" % user.username
```
* Django application

```python
from django.http import HttpResponse
from django.db import connection

def hello(request):
    id = request.GET.get("id", "")
    cursor = connection.cursor()
    cursor.execute("SELECT username FROM auth_user WHERE id=:id", {"id": id}) # Compliant
    row = cursor.fetchone()
    return HttpResponse("Hello %s" % row[0])
```

## Risk Assessment
Injection flaws are very prevalent, particularly in legacy code. Injection vulnerabilities are often ound
in SQL, LDAP, XPath, or NoSQL queries, OS commands, XML parsers, SMTP headers, expression languages, and ORM queries.
Injection flaws are easy to discover when examining code. Scanners and fuzzers can help attackers find injection flaws.

## References
* [A1:2017-Injection]
* [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')]
* [CWE-564: SQL Injection: Hibernate]
* [CWE-20: Improper Input Validation]
* [CWE-943: Improper Neutralization of Special Elements in Data Query Logic]

[A1:2017-Injection]:https://owasp.org/www-project-top-ten/2017/A1_2017-Injection.html
[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')]:https://cwe.mitre.org/data/definitions/89
[CWE-564: SQL Injection: Hibernate]:https://cwe.mitre.org/data/definitions/564.html
[CWE-20: Improper Input Validation]:https://cwe.mitre.org/data/definitions/20.html
[CWE-943: Improper Neutralization of Special Elements in Data Query Logic]:https://cwe.mitre.org/data/definitions/943.html
