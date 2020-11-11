# Dynamic Code Execution Vulnerability

## Description
Dynamic code execution should not be vulnerable to injection attacks. Applications that execute code dynamically should neutralize any externally-provided values used to construct the code. Failure to do so could allow an attacker to execute arbitrary code. This could enable a wide range of serious attacks like accessing/modifying sensitive information or gain full system access.

The mitigation strategy should be based on whitelisting of allowed values or casting to safe types.


## Vulnerable Code Example

```python
from flask import request

@app.route('/')
def index():
    module = request.args.get("module")
    exec("import urllib%s as urllib" % module) # N
```


## Mitigation

```python
from flask import request

@app.route('/')
def index():
    module = request.args.get("module")
    exec("import urllib%d as urllib" % int(module)) # Compliant; module is safely cast to an integer
```

## Risk Assessment
Injection can result in data loss, corruption, or disclosure to unauthorized parties, loss of accountability, or denial of access. Injection can sometimes lead to complete host takeover.
The business impact depends on the needs of the application and data.


## References
* [A1:2017-Injection]
* [CWE-94: Improper Control of Generation of Code ('Code Injection')]
* [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')]



[A1:2017-Injection]:https://owasp.org/www-project-top-ten/2017/A1_2017-Injection.html
[CWE-94: Improper Control of Generation of Code ('Code Injection')]:https://cwe.mitre.org/data/definitions/94.html
[CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')]:https://cwe.mitre.org/data/definitions/95.html
