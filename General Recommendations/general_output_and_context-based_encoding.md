# Encoding and Escaping

## Description

Both encoding and escaping are code defensive strategies that are meant to prevent injection attacks. When it comes to encoding or commonly known as Output Encoding, it can be defined as the process of translating special characters into something different but equivalent that is not longer dangerous in the interpreter.

As an example of Encoding, the character *<* will be represented as *&alt;* when is echoed into an HTML page.

Escaping, in the other hand, is the process of *adding* special characters before a given string to avoid misinterpretations, for example using the character \ before a double quote (") so the string can be interpreted as text and not as closing a string.

Here is an example of escaping double quotes in the python language.

```python
text = "This is a text \"very\" extense"
```

To defeat security flaws such as Cross-Site Scripting (XSS), *Contextual Output Encoding* has been a very good code defense. This technique consists on applying the encoding functions just before it is output.

It is called contextual encoding because the type of encoding will depend on the location (context) in the HTML where the output will be rendered. Some of these contexts are:
* HTML Entity Encoding
* HTML Attribute Encoding
* JavaScript Encoding
* URL Encoding

An example of URL Encoding is displayed below

```HTML

An URL like this:

https://www.secureshopping.com/product=Secure Programming Books 2020

It is URL-encoded as this:

https%3A%2F%2Fwww.secureshopping.com%2Fproduct%3DSecure%20Programming%20Books%202020

## Tools and Libraries to perform Output Encoding
```

* For Java related projects please refer to the [OWASP Java Encoder](https://owasp.org/www-project-java-encoder/#tab=Use_the_Java_Encoder_Project) or visit the [GitHub repo](https://github.com/OWASP/owasp-java-encoder)


```java
PrintWriter out = ....;
    out.println("<textarea>"+Encode.forHtml(userData)+"</textarea>");
```

* For .NET Encoding, .NET Framework 4.5 and upper already added the Anti-Cross Site Scripting library within the framework but its not enabled by default.

Visit [Prevent Cross-Site Scripting (XSS) in ASP.NET Core](https://docs.microsoft.com/en-us/aspnet/core/security/cross-site-scripting?view=aspnetcore-5.0) for a better understanding on how to mitigate these issues on Microsoft .NET

* PHP Zend Framework provides Context-specific Scaping using the so-called [zend-escaper](https://framework.zend.com/blog/2017-05-16-zend-escaper.html)

```php
use Zend\Escaper\Escaper;
$escaper = new Escaper();

echo $escaper->escapeHtml('<script>alert("zf")</script>');
// results in "&lt;script&gt;alert(&quot;zf&quot;)&lt;/script&gt;"

echo $escaper->escapeHtmlAttr("<script>alert('zf')</script>");
// results in "&lt;script&gt;alert&#x28;&#x27;zf&#x27;&#x29;&lt;&#x2F;script&gt;"

echo $escaper->escapeJs("bar&quot;; alert(&quot;zf&quot;); var xss=&quot;true");
// results in "bar\x26quot\x3B\x3B\x20alert\x28\x26quot\x3Bzf\x26quot\x3B\x29\x3B\x20var\x20xss\x3D\x26quot\x3Btrue"
```

# References
[OWASP Proactive controls C4: Encode and Escape Data](https://owasp.org/www-project-proactive-controls/v3/en/c4-encode-escape-data)

[Input validation or output filtering, which is better?](https://blog.jeremiahgrossman.com/2007/01/input-validation-or-output-filtering.html)

[OWASP Java Encoder](https://owasp.org/owasp-java-encoder/encoder/index.html)

[Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
