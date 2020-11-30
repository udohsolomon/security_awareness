# Cross-Site Scripting (XSS)

## Description

XSS attacks are one of the most prevalent security flaws and mainly they occur when an application includes user-supplied data that is sent to the browser without proper input data validation or sanitization.

There are three types of XSS flaws:
* Stored
* Reflected
* DOM-based XSS attacks

For a deep understanding on the risks associated to XSS from JavaScript, please refer to [[Security] OWASP Top 10 for JavaScript - A2: Cross-Site Scripting - XSS](https://erlend.oftedal.no/blog/static-127.html).


# Code examples

Let's assume that we have a Web application that writes down in a div, the data that came from a text form or dropdown list that the user selected:

```html
<div class="data"/>
````

Here is the JavaScript code:

```JavaScript
var input = $("txtCommend").val();
$('.data').html(input);

// If the user sends this payload:
// '<script>alert("XSS");</script\>'
// It will evaluate the this code, 

```

# Mitigation

If JQuery is being used, an effective way is to use the function [text()](https://api.jquery.com/text/#text2):

``` JavaScript
// Having a div as follows:
//<div class="message"> some text goes here </div>

var userData = "<script>alert('xss');</script>";

$("div.message").text(userData);
// it produces:
// <div class="message">&lt;script&gt;alert('xss');&lt;/script&gt;</div>

// getting the text as string
var escapedString = $("<div>").text(userData).html();
// output: 
// &lt;script&gt;alert('xss');&lt;/script&gt;
```

Additionally, folks from [mustache.js](https://github.com/janl/mustache.js/) implemented the following code to perform [HTML escaping](https://github.com/janl/mustache.js/blob/master/mustache.js#L78) and remediate this issue, the code can be found at their github repository and goes like this:

```JavaScript

var entityMap = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;',
    '`': '&#x60;',
    '=': '&#x3D;'
  };

  function escapeHtml (string) {
    return String(string).replace(/[&<>"'`=\/]/g, function fromEntityMap (s) {
      return entityMap[s];
    });
  }

```

It is strongly recommended to use a security-focused encoding library. For example, for JavaScript serialization to JSON, it is recommended to use  [Yahoo's Serialize JavaScript](https://github.com/yahoo/serialize-javascript) because it provides an automatic escaping HTML Characters.

## Risk Assessment

Cross-Site Scripting is considered moderate to severe vulnerabilities. The most severe type of XSS is stored ith remote code execution on the victim’s browser, such as stealing credentials, sessions, or delivering malware to the victim.

## References

[A7:2017-Cross-Site Scripting (XSS)](https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS))

[Cross Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)

[DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)

