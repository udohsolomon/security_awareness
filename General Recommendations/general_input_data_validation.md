# Input Data Validation: The user can send arbitrary data

## Description

From its definition, a software program consists of an input, a processing layer, and an output. Input is essential for a program to work properly. However, this input can come from multiple places: from the end-user via HTTP methods or HTML forms, via HTTP headers and cookies, from external entities such as third-parties via Web Services invocations, and even from other applications via database queries. 

This dynamic nature of input data requires developers to adopt a security posture at the time of writing code; that is a defensive programming style where input data is properly validated before it is being processed. This posture needs to be applied in the front-end layer (via client-side validations of the input) and at the back-end logic (since most of the time threat actors won't use a Web browser to interact with the application).

Most prevalent Web application attacks involve sending input to a server that was crafted to cause unexpected behavior that was not desired by the application's developers and designers.

Additionally, the current landscape for threat profiles evolves very rapidly and customer-facing applications are being actively used by such groups to compromise the organization, steal sensitive information, disseminate malware and ransomware, and other severe consequences for the business.

Given this, input data validation is a key player in securing an application and avoiding that a malicious user can send arbitrary data to such an application. The rule of thumb is that all input must be properly validated.

*Note that when input is not properly validated is classified as Improper Input Validation and there exists a CWE (Common Weakness Enumeration) for it called [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

## Approaches for performing Input Validation

Generally speaking, there are two categories on how the input should be validated and one of them is more effective than the other:

* Black Listing: This mechanism consist in checking if the input matches known-bad content, for example, if we are validating if the user is sending arbitrary SQL syntax in the input, in a blacklist approach would be checking if the input contains SQL keywords such as *select, insert, update and delete*. However, this approach is not recommended because on one hand is easier to evade and as new attack vector evolves very rapidly, the solution provided will also be evaded by a threat actor, also **Black Listing is prone to error and it is not recommended as a standard security practice**.
* White Listing: This mechanism consist on validating if the input matches good-known rules or criteria. This way any input that is not aligned to this state will be rejected. For instance, if the input field expects an email address, developers can use a tested regular expression such as 
  ```^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$```. Developers can refer to [OWASP Validation Regex Repository](https://owasp.org/www-community/OWASP_Validation_Regex_Repository) to ensure their regular expressions are safe (using an incorrect, non-tested regular expression pattern could lead to denial-of-service condition, see [Regular expression Denial of Service - ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS) ).

## Recommendations 
Input Validation, using a Whitelisting approach can be performed following these validation rules:
* **Lenght**: For example, ff the application expects an email address, this value should not be larger than 20-25 characters, so if the application receives a larger value, the input could be rejected because it won't match the constraints in the database for the column size. 
* **Format**: Another way to perform validations is by analyzing the format in which this input is expected. Here, regular expressions are very handy; developers can use safe regular expressions to determine whether or not the input received matches the expected values.
* **Data type**: Development frameworks such as [Apache Commons](https://commons.apache.org/proper/commons-validator/apidocs/org/apache/commons/validator/package-summary.html#doc.Usage.validator). Microsoft also provides a [DataType enumeration](https://docs.microsoft.com/en-us/dotnet/api/system.componentmodel.dataannotations.datatype?view=net-5.0) that associates a data field and parameters with an expected data type:

```c#
using System;
using System.Web.DynamicData;
using System.ComponentModel.DataAnnotations;

[MetadataType(typeof(CustomerMetaData))]
public partial class Customer
{
}

public class CustomerMetaData
{

    // Add type information.
    [DataType(DataType.EmailAddress)]
    public object EmailAddress;
}
```

## References
[Input Validation - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)

[C5: Validate All Input](https://owasp.org/www-project-proactive-controls/v3/en/c5-validate-inputs)

[CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

[Regular expression Denial of Service - ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)