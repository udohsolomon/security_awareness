# HTTP Request Redirect Vulnerability

## Description
User provided data, such as URL parameters, POST data payloads, or cookies, should always be considered untrusted and tainted. Applications performing HTTP redirects based on tainted data could enable an attacker to redirect users to a malicious site to, for example, steal login credentials.

This problem could be mitigated in any of the following ways:

* Validate the user provided data based on a whitelist and reject input not matching.
* Redesign the application to not perform redirects based on user provided data.

## Vulnerable Code Example
* Flask

```python
from flask import request, redirect

@app.route('move')
def move():
    url = request.args["next"]
    return redirect(url) # Noncompliant
```
* Django

```python
from django.http import HttpResponseRedirect

def move(request):
    url = request.GET.get("next", "/")
    return HttpResponseRedirect(url) # Noncompliant
```

## Mitigation
* Flask

```python
from flask import request, redirect, url_for

@app.route('move')
def move():
    endpoint = request.args["next"]
    return redirect(url_for(endpoint)) # Compliant
```
* Django
```python
from django.http import HttpResponseRedirect
from urllib.parse import urlparse

DOMAINS_WHITELIST = ['www.example.com', 'example.com']

def move(request):
    url = request.GET.get("next", "/")
    parsed_uri = urlparse(url)
    if parsed_uri.netloc in DOMAINS_WHITELIST:
        return HttpResponseRedirect(url) # Compliant
    return HttpResponseRedirect("/")
```

## Risk Assessment
The technical impact is attackers acting as users or administrators, or users using privileged functions, or creating, accessing, updating or deleting every record.
The business impact depends on the protection needs of the application and data.


## References
* [A5:2017-Broken Access Control]
* [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')]



[A5:2017-Broken Access Control]:https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control.html
[CWE-601: URL Redirection to Untrusted Site ('Open Redirect')]:https://cwe.mitre.org/data/definitions/601.html

