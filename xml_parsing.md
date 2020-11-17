# XML parsing vulnerable to XXE

## Description
XML specification allows the use of entities that can be internal or external (file system / network access ...) which could lead to vulnerabilities such as confidential file disclosures or SSRFs.

XML External Entity (XXE) attacks can occur when an XML parser supports XML entities while processing XML received from an untrusted source.

### Risk 1: Expose local file content (XXE: XML External Entity)

```java
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
   <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
<foo>&xxe;</foo>
```
### Risk 2: Denial of service (XEE: XML Entity Expansion)
```java
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
   <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
<foo>&xxe;</foo>
```
```java
<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ELEMENT lolz (#PCDATA)>
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
[...]
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

## Vulnerable Code Example 1

```java
DocumentBuilder builder = df.newDocumentBuilder();

XPathFactory xPathFactory = XPathFactory.newInstance();
XPath xpath = xPathFactory.newXPath();
XPathExpression xPathExpr = xpath.compile("/somepath/text()");

xPathExpr.evaluate(new InputSource(inputStream));
```
## Vulnerable Code Example 2
```java
const libxmljs = require("libxmljs");
var fs = require('fs');

var xml = fs.readFileSync('xxe.xml', 'utf8');

var xmlDoc = libxmljs.parseXmlString(xml, { noblanks: true, noent: true, nocdata: true }); // Noncompliant: noent set to true
```

## Mitigation

```java
const libxmljs = require("libxmljs");
var fs = require('fs');

var xml = fs.readFileSync('xxe.xml', 'utf8');

var xmlDoc = libxmljs.parseXmlString(xml); // Compliant: noent set to false by default
```


## Risk Assessment
These flaws can be used to extract data, execute a remote request from the server, scan internal systems, perform a denial-of-service attack, as well as execute other attacks. The business impact depends on the protection needs of all affected application and data.


## References
* [A4:2017-XML External Entities (XXE)]
* [XML External Entity Prevention Cheat Sheet]
* [CWE-611: Improper Restriction of XML External Entity Reference]
* [CWE-827: Improper Control of Document Type Definition]



[A4:2017-XML External Entities (XXE)]:https://owasp.org/www-project-top-ten/2017/A4_2017-XML_External_Entities_(XXE).html
[XML External Entity Prevention Cheat Sheet]:https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
[CWE-611: Improper Restriction of XML External Entity Reference]:https://cwe.mitre.org/data/definitions/611.html
[CWE-827: Improper Control of Document Type Definition]:https://cwe.mitre.org/data/definitions/827.html

