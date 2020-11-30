# Regular expression Denial of Service - ReDoS

## Description

Regular expression Denial of Service (ReDos) is a type of Denial of Service attack in which a regular expression pattern is used that could reach extreme situations causing them to work very slow (with an exponential growth relative to input size).

Regular expression patterns are publicly available on the Internet. A developer might inadvertently add a regular expression to the source code that could cause this problem.

Unlike a Distributed Denial of Service DDOS with huge amount of traffic hitting a target, a Regular Expression Denial of Service can bring down an application or Web Servive with just a few requests.


# Sample Code

Following regex patterns are known to cause exponential growths 

```regex
(a+)+
([a-zA-Z]+)*
(a|aa)+
(a|a?)+
(.*a){x} for x \> 10

//Email regex that causes DoS

^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$

//When an iput like this is provided:
# aaaaaaaaaaaaaaaaaaaaaaaaaaa!
```

# Remediation

When using regular expressions it's recommended to perform unit testing with small and large datasets, a good technique for doing so is by using Fuzzing techniques and be able to identify those regular expression patterns that could cause a denial of service.

OWASP provides a curated list of regular expressions that are safe to use, although it is always recommended to test them out before. The project is called [OWASP Validation Regex Repository](https://owasp.org/www-community/OWASP_Validation_Regex_Repository).

## Risk Assessment

Regular Expression Denial of Service (ReDoS) can result on making a Web application or Service unavailable. Here is an interesting article that describes the impact of this vulnerability on a large provides such as Cloudflare [Details of the Cloudflare outage on July 2, 2019](https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/).

Depending on the criticality of the asset being affected, risk could be severe or moderate.

## References:
[Details of the Cloudflare outage on July 2, 2019](https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/)

[How Regular Expressions and a WAF DoS-ed Cloudflare](https://www.acunetix.com/blog/web-security-zone/regular-expressions-waf-cloudflare/)