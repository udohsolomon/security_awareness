# Buffer Overflow

## Description
Buffer overflows are probably one of the most vicious tools available to an attacker. A small honest mistake made by a developer with SETUID root permissions can mean catastrophe. 

A buffer overflow is the technique of overwriting machine code with an attackers own code, this occurs when a program takes input from a user in low-level languages such as c, c++ without checking its size. It can be used to gain root access.

To effectively mitigate buffer overflow vulnerabilities, it is important to understand what buffer overflows are, what dangers they pose to your applications, and what techniques attackers use to successfully exploit these vulnerabilities.

## Vulnerabilities

## gets()
The stdio gets() function does not check for buffer length and always results in a vulnerability.

```c
#include <signal.h>
#include <stdio.h>
#include <string.h>
int main () {
    char username[8];
    int allow = 0;
    printf("Enter your username, please: ");
    gets(username); // user inputs "malicious"
    if (grantAccess(username)) {
        allow = 1;
    }
    if (allow != 0) { // has been overwritten by the overflow of the username.
        privilegedAction();
    }
    return 0;
}
```
### Mitigation
Prefer using fgets (and dynamically allocated memory!):
```c
#include <stdio.h>
#include <stdlib.h>
#define LENGTH 8
int main () {
    char* username, *nlptr;
    int allow = 0;
 
    username = malloc(LENGTH * sizeof(*username));
    if (!username)
        return EXIT_FAILURE;
    printf("Enter your username, please: ");
    fgets(username,LENGTH, stdin);
    // fgets stops after LENGTH-1 characters or at a newline character, which ever comes first.
    // but it considers \n a valid character, so you might want to remove it:
    nlptr = strchr(username, '\n');
    if (nlptr) *nlptr = '\0';
 
    if (grantAccess(username)) {
        allow = 1;
    }
    if (allow != 0) {
        priviledgedAction();
    }
 
    free(username);
 
    return 0;
}
```
## strcpy
The strcpy built-in function does not check buffer lengths and may very well overwrite memory zone contiguous to the intended destination. In fact, the whole family of functions is similarly vulnerable: strcpy, strcat and strcmp.
```c
char str1[10];
char str2[]="abcdefghijklmn";
strcpy(str1,str2);
```

### Mitigation
The best way to mitigate this issue is to use strlcpy if it is readily available (which is only the case on BSD systems). However, it is very simple to define it yourself, as shown below:

```c
#include <stdio.h>
#ifndef strlcpy
#define strlcpy(dst,src,sz) snprintf((dst), (sz), "%s", (src))
#endif
 
enum { BUFFER_SIZE = 10 };
 
int main() {
    char dst[BUFFER_SIZE];
    char src[] = "abcdefghijk";
 
    int buffer_length = strlcpy(dst, src, BUFFER_SIZE);
 
    if (buffer_length >= BUFFER_SIZE) {
        printf("String too long: %d (%d expected)\n",
                buffer_length, BUFFER_SIZE-1);
    }
 
    printf("String copied: %s\n", dst);
 
    return 0;
}
```
## sprintf
Just as the previous functions, sprintf does not check the buffer boundaries and is vulnerable to overflows.
```c
#include <stdio.h>
#include <stdlib.h>
 
enum { BUFFER_SIZE = 10 };
 
int main() {
    char buffer[BUFFER_SIZE];
    int check = 0;
 
    sprintf(buffer, "%s", "This string is too long!");
 
    printf("check: %d", check); /* This will not print 0! */
 
    return EXIT_SUCCESS;
}
```
### Mitigation
Prefer using snprintf, which has the double advantage of preventing buffers overflows and returning the minimal size of buffer needed to fit the whole formatted string.
```c
#include <stdio.h>
#include <stdlib.h>
 
enum { BUFFER_SIZE = 10 };
 
int main() {
    char buffer[BUFFER_SIZE];
 
    int length = snprintf(buffer, BUFFER_SIZE, "%s%s", "long-name", "suffix");
 
    if (length >= BUFFER_SIZE) {
        /* handle string truncation! */
    }
 
    return EXIT_SUCCESS;
}
```
## printf
One other vulnerability category is concerned with string formatting attacks, those can cause information leakage, overwriting of memory, … This error can be exploited in any of the following functions: printf, fprintf, sprintf and snprintf, i.e. all functions that take a “format string” as argument.

```c
#FormatString.c
#include <stdio.h>
 
int main(int argc, char **argv) {
    char *secret = "This is a secret!\n";
 
    printf external link(argv[1]);
 
    return 0;
}
```
Now, this code, if compiled with the -mpreferred-stack-boundary=2 option (on a 32-bit platform; on 64-bit things work slightly differently, but the code still is vulnerable!), can yield interesting results.

If called with ```./FormatString %s```, it will print the secret string.

```c
$ gcc -mpreferred-stack-boundary=2 FormatString.c -o FormatString
$ ./FormatString %s
This is a secret!
$
```
### Mitigation
It's really simple: always hardcode the format string. At least, never let it come directly from any user's input.

## File opening
Much care must be taken when opening files, as many issues can arise. Out of the many ways file handling can be attacked, we will only present two brief examples below.

### Symbolic link attack
It is a good idea to check whether a file exists or not before creating it. However, a malicious user might create a file (or worse, a symbolic link to a critical system file) between your check and the moment you actually use the file.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
 
#define MY_TMP_FILE "/tmp/file.tmp"
 
 
int main(int argc, char* argv[])
{
    FILE * f;
    if (!access(MY_TMP_FILE, F_OK)) {
        printf external link("File exists!\n");
        return EXIT_FAILURE;
    }
    /* At this point the attacker creates a symlink from /tmp/file.tmp to /etc/passwd */
    tmpFile = fopen(MY_TMP_FILE, "w");
 
    if (tmpFile == NULL) {
        return EXIT_FAILURE;
    }
 
    fputs("Some text...\n", tmpFile);
 
    fclose(tmpFile);
    /* You successfully overwrote /etc/passwd (at least if you ran this as root) */
 
    return EXIT_SUCCESS;
}
```
### Mitigation
Avoid the race condition by accessing directly the file, and don't overwrite it if it already exists.
```c
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
 
#define MY_TMP_FILE "/tmp/file.tmp"
 
enum { FILE_MODE = 0600 };
 
int main(int argc, char* argv[])
{
    int fd;
    FILE* f;
 
    /* Remove possible symlinks */
    unlink(MY_TMP_FILE);
    /* Open, but fail if someone raced us and restored the symlink (secure version of fopen(path, "w") */
    fd = open(MY_TMP_FILE, O_WRONLY|O_CREAT|O_EXCL, FILE_MODE);
    if (fd == -1) {
        perror("Failed to open the file");
        return EXIT_FAILURE;
    }
    /* Get a FILE*, as they are easier and more efficient than plan file descriptors */
    f = fdopen(fd, "w");
    if (f == NULL) {
        perror("Failed to associate file descriptor with a stream");
        return EXIT_FAILURE;
    }
    fprintf(f, "Hello, world\n");
    fclose(f);
    /* fd is already closed by fclose()!!! */
    return EXIT_SUCCESS;
}
```


## General Mitigation Strategies
1. Address space randomization (ASLR)—randomly moves around the address space locations of data regions. Typically, buffer overflow attacks need to know the locality of executable code, and randomizing address spaces makes this virtually impossible.
2. Data execution prevention—flags certain areas of memory as non-executable or executable, which stops an attack from running code in a non-executable region.
3. Structured exception handler overwrite protection (SEHOP)—helps stop malicious code from attacking Structured Exception Handling (SEH), a built-in system for managing hardware and software exceptions. It thus prevents an attacker from being able to make use of the SEH overwrite exploitation technique. At a functional level, an SEH overwrite is achieved using a stack-based buffer overflow to overwrite an exception registration record, stored on a thread’s stack.
4. Avoid functions that do no bounds checking

| Instead Of    | Use           |
| ------------- |:-------------:|
| gets()        | fgets()       | 
| strcpy()      | strncpy()     | 
| strcat()      | strncat()     |
| sprintf()     | bcopy()       |
| scanf()       | bzero()       |
| sscanf()      | memcpy(), memset()|
5. Be especially careful programming and/or installing setuid root programs and programs that run as root. These are the programs that allow an attacker to acquire a root shell.
6. Be careful when using for and while loops that copy data from one variable to another. Make sure the bounds are checked.
7. Review legacy software code for security problems.

## References
* [OWASP Buffer Overflow Attack]
* [Veracode: What Is a Buffer Overflow? Learn About Buffer Overrun Vulnerabilities, Exploits & Attacks]

[OWASP Buffer Overflow Attack]:https://owasp.org/www-community/attacks/Buffer_overflow_attack
[Veracode: What Is a Buffer Overflow? Learn About Buffer Overrun Vulnerabilities, Exploits & Attacks]:https://www.veracode.com/security/buffer-overflow
[Common vulnerabilities guide for C programmers]:https://security.web.cern.ch/recommendations/en/codetools/cpp.shtml

