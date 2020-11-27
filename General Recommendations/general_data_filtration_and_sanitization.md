# Input Data Filtering and Sanitization

# Description

Input validation, filtering, and sanitization is the foundation of application security. In essence, filtering is the process of validating input data and preventing invalid data from being used by the application's logic.

It's not common to see that most of the time, the front-end layer provides a rich set of validations (whether the field is mandatory, whether it matches the format expected, whether it matches certain policy). However, developers forgot to implement the same validations at the server-side.

# Data Filtering examples

Programming Languages provides some tools for performing Data Filtering. As shown in the below code, C# provides data annotations to validate data and avoid that unwanted inputs are processed.

```csharp

using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace MvcApplication1.Models
{
    
    public class Product
    {
        public int Id { get; set; }

        [Required]
        [StringLength(10)]
        public string Name { get; set; }

        [Required]
        public string Description { get; set; }

        [DisplayName("Price")]
        [RegularExpression(@"^\$?\d+(\.(\d{2}))?$")]
        public decimal UnitPrice { get; set; }
    }
}
```
Input filtering can be performed by the developer based on the accepted criteria from the application.

``` node
POST /api/realtime-transfer
{
    "from"   :"1000001",
    "to"     :"2000001",
    "amount" : 300
}

const { check, validationResult } = require('express-validator'); 

app.post('/api/realtime-transfer', [
  var from     = req.body.from;
  var to       = req.body.to;
  var amount   = req.body.amount;
  check('from', 'From account should contains 7 digits ').isLength({ min: 7, max: 7 }), 
  check('to', 'To account should contains 7 digits ').isLength({ min: 7, max: 7 }), 
  check('amount', 'Amount to transfer must be a numeric value').isNumeric()

], (req , res ) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
  }
}
})

```

Simple rules like this will allow to filter input data that comes from the user.

## Sanitization

Sanitization is the process to guarantee that not only that data comes in the right format but also that is free of noise. During the sanitization process, some characters can be transformed from the original input string, either by removing them, replacing them, encoding them, or escaping them.

Most programming languages provides packages or libraries for performing data sanitization.

The following code is an example on how this can be achieved in node.js via the [express-validator npm package](https://express-validator.github.io/docs/sanitization.html).

```node

const express  = require('express');
const { body } = require('express-validator');

const app = express();
app.use(express.json());

app.post('/comment', [
  body('email')
    .isEmail()
    .normalizeEmail(),
  body('text')
    .not().isEmpty()
    .trim()
    .escape(),
  body('notifyOnReply').toBoolean()
], (req, res) => {
  // Handle the request somehow
});

```
Note that it uses some sanitizations such as [normalize email](https://github.com/validatorjs/validator.js/blob/e3f9d2b6e1c5a5ee1589be06ffeda0c76bf60bde/src/lib/normalizeEmail.js) and escaping functions.

In .net, the [HtmlSanitizer NuGet package](https://www.nuget.org/packages/HtmlSanitizer), provides a similar approach

```csharp
var sanitizer = new HtmlSanitizer();
var html = @"<script>alert('xss')</script><div onload=""alert('xss')"""
    + @"style=""background-color: test"">Test<img src=""test.gif"""
    + @"style=""background-image: url(javascript:alert('xss')); margin: 10px""></div>";
var sanitized = sanitizer.Sanitize(html, "http://www.example.com");
Assert.That(sanitized, Is.EqualTo(@"<div style=""background-color: test"">"
    + @"Test<img style=""margin: 10px"" src=""http://www.example.com/test.gif""></div>"));
```

# References
[HtmlSanitizer](https://github.com/mganss/HtmlSanitizer)

[express-validator](https://express-validator.github.io/docs/index.html)

[Validation with the Data Annotation Validators (C#)](https://docs.microsoft.com/en-us/aspnet/mvc/overview/older-versions-1/models-data/validation-with-the-data-annotation-validators-cs)

[Input validations or output filtering, which is better?](https://blog.jeremiahgrossman.com/2007/01/input-validation-or-output-filtering.html)
