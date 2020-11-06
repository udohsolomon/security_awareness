# Improper Restriction of Operations within the Bounds of a Memory Buffer Vulnerability

## Description
Do not make any assumptions about the size of environment variables because an adversary might have full control over the environment. If the environment variable needs to be stored, the length of the associated string should be calculated and the storage dynamically allocated

## Vulnerable Code Example
This vulnerable code example copies the string returned by ```getenv()``` into a fixed-size buffer:

```c
void f() {
  char path[PATH_MAX]; /* Requires PATH_MAX to be defined */
  strcpy(path, getenv("PATH"));
  /* Use path */
}
```
Even if your platform assumes that ```$PATH``` is defined, defines ```PATH_MAX```, and enforces that paths not have more than PATH_MAX characters, the $PATH environment variable still is not required to have less than ```PATH_MAX``` chars. And if it has more than ```PATH_MAX``` chars, a buffer overflow will result. Also, if ```$PATH``` is not defined, then ```strcpy()``` will attempt to dereference a null pointer.

## Mitigation
In this compliant solution, the ```strlen()``` function is used to calculate the size of the string, and the required space is dynamically allocated:

```c
void f() {
  char *path = NULL;
  /* Avoid assuming $PATH is defined or has limited length */
  const char *temp = getenv("PATH");
  if (temp != NULL) {
    path = (char*) malloc(strlen(temp) + 1);
    if (path == NULL) {
      /* Handle error condition */
    } else {
      strcpy(path, temp);
    }
    /* Use path */
    free(path);
  }
}
```

## Risk Assessment
Making assumptions about the size of an environmental variable can result in a buffer overflow.


## References
* [CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer]
* [Programming Languages—C, 3rd ed (ISO/IEC 9899:2011). Geneva, Switzerland: ISO, 2011.]

[CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer]:https://cwe.mitre.org/data/definitions/119.html
[Programming Languages—C, 3rd ed (ISO/IEC 9899:2011). Geneva, Switzerland: ISO, 2011.]:https://wiki.sei.cmu.edu/confluence/display/c/AA.+Bibliography#AA.Bibliography-ISO-IEC9899-2011
