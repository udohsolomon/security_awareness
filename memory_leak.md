# Memory Leak Vulnerability

## Description
Developers should take steps to prevent sensitive information such as passwords, cryptographic keys, and other secrets from being inadvertently leaked. Preventive measures include attempting to keep such data from being written to disk.

Two common mechanisms by which data is inadvertently written to disk are swapping and core dumps.

Many general-purpose operating systems implement a virtual-memory-management technique called paging (also called swapping) to transfer pages between main memory and an auxiliary store, such as a disk drive. This feature is typically implemented as a task running in the kernel of the operating system, and its operation is invisible to the running program.

A core dump is the recorded state of process memory written to disk for later examination by a debugger. Core dumps are typically generated when a program has terminated abnormally, either through an error resulting in a crash or by receiving a signal that causes such a termination.

The POSIX standard system call for controlling resource limits, setrlimit(), can be used to disable the creation of core dumps, which prevents an attacker with the ability to halt the program from gaining access to sensitive data that might be contained in the dump.

## Vulnerable Code Example
In this code example, sensitive information is supposedly stored in the dynamically allocated buffer, secret, which is processed and eventually cleared by a call to ```memset_s()```. The memory page containing secret can be swapped out to disk. If the program crashes before the call to ```memset_s()``` completes, the information stored in secret may be stored in the core dump.

```c
char *secret;
 
secret = (char *)malloc(size+1);
if (!secret) {
  /* Handle error */
}
 
/* Perform operations using secret... */
 
memset_s(secret, '\0', size+1);
free(secret);
secret = NULL;
```
## Mitigation
To prevent the information from being written to a core dump, the size of core dumps that the program will generate should be set to 0 using ```setrlimit()```:
```c
#include <sys/resource.h>
/* ... */
struct rlimit limit;
limit.rlim_cur = 0;
limit.rlim_max = 0;
if (setrlimit(RLIMIT_CORE, &limit) != 0) {
    /* Handle error */
}
 
char *secret;
 
secret = (char *)malloc(size+1);
if (!secret) {
  /* Handle error */
}
 
/* Perform operations using secret... */
 
memset_s(secret, '\0', size+1);
free(secret);
secret = NULL;
```

## Mitigation (Privileged Process, POSIX)

The added security from using mlock() is limited.
Processes with elevated privileges can disable paging by locking memory in place using the POSIX mlock() function. Disabling paging ensures that memory is never copied to the hard drive, where it may be retained indefinitely in nonvolatile storage.
This compliant solution not only disables the creation of core files but also ensures that the buffer is not swapped to hard disk:
```c
#include <sys/resource.h>
/* ... */
struct rlimit limit;
limit.rlim_cur = 0;
limit.rlim_max = 0;
if (setrlimit(RLIMIT_CORE, &limit) != 0) {
    /* Handle error */
}
 
long pagesize = sysconf(_SC_PAGESIZE);
if (pagesize == -1) {
  /* Handle error */
}
 
char *secret_buf;
char *secret;
 
secret_buf = (char *)malloc(size+1+pagesize);
if (!secret_buf) {
  /* Handle error */
}
 
/* mlock() may require that address be a multiple of PAGESIZE */
secret = (char *)((((intptr_t)secret_buf + pagesize - 1) / pagesize) * pagesize);
 
if (mlock(secret, size+1) != 0) {
    /* Handle error */
}
 
/* Perform operations using secret... */
 
if (munlock(secret, size+1) != 0) {
    /* Handle error */
}
secret = NULL;
 
memset_s(secret_buf, '\0', size+1+pagesize);
free(secret_buf);
secret_buf = NULL;
```
## Risk Assessment
Writing sensitive data to disk preserves it for future retrieval by an attacker, who may even be able to bypass the access restrictions of the operating system by using a disk maintenance program.


## References
* [CWE-528: Information leak through core dump files]
* [Information Technology-Programming Languages—Guidance to Avoiding Vulnerabilities in Programming Languages through Language Selection and Use. Geneva, Switzerland: ISO, March 2013]

[CWE-528: Information leak through core dump files]:https://cwe.mitre.org/data/definitions/528.html
[Information Technology-Programming Languages—Guidance to Avoiding Vulnerabilities in Programming Languages through Language Selection and Use. Geneva, Switzerland: ISO, March 2013]:https://wiki.sei.cmu.edu/confluence/display/c/AA.+Bibliography#AA.Bibliography-ISO-IECTR24772-2013
