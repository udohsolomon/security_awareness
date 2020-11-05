# Use After Free (UAF) Vulnerability

## Description
The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timing of the flaw. The simplest way data corruption may occur involves the system's reuse of the freed memory. 

Use-after-free errors have two common and sometimes overlapping causes:

* Error conditions and other exceptional circumstances.
* Confusion over which part of the program is responsible for freeing the memory.

In this scenario, the memory in question is allocated to another pointer validly at some point after it has been freed. The original pointer to the freed memory is used again and points to somewhere within the new allocation. As the data is changed, it corrupts the validly used memory; this induces undefined behavior in the process.

## Vulnerable Code Example
In this vulnerable code example, the type of a message is used to determine how to process the message itself. It is assumed that message_type is an integer and message is a pointer to an array of characters that were allocated dynamically. If ```message_type``` equals ```value_1```, the message is processed accordingly. A similar operation occurs when ```message_type``` equals ```value_2```. However, if ```message_type == value_1``` evaluates to true and ```message_type == value_2``` also evaluates to true, then message is freed twice, resulting in a double-free vulnerability.

```c

char *message;
int message_type;
 
/* Initialize message and message_type */
 
if (message_type == value_1) {
  /* Process message type 1 */
  free(message);
}
/* ...*/
if (message_type == value_2) {
   /* Process message type 2 */
  free(message);
}
```
## Mitigation
Calling ```free()``` on a null pointer results in no action being taken by ```free()```. Setting message to ```NUL```L after it is freed eliminates the possibility that the message pointer can be used to free the same memory more than once.

```c
char *message;
int message_type;
 
/* Initialize message and message_type */
 
if (message_type == value_1) {
  /* Process message type 1 */
  free(message);
  message = NULL;
}
/* ... */
if (message_type == value_2) {
  /* Process message type 2 */
  free(message);
  message = NULL;
}
```

## Risk Assessment
Setting pointers to NULL or to another valid value after memory is freed is a simple and easily implemented solution for reducing dangling pointers. Dangling pointers can result in freeing memory multiple times or in writing to memory that has already been freed. Both of these problems can lead to an attacker executing arbitrary code with the permissions of the vulnerable process.

## References
* [CWE-416: Use After Free]
* [C Secure Coding Rules: Past, Present, and Future, Seacord, Robert C, 2013.]

[CWE-416: Use After Free]:https://cwe.mitre.org/data/definitions/416.html
[C Secure Coding Rules: Past, Present, and Future, Seacord, Robert C, 2013.]:https://www.informit.com/articles/article.aspx?p=2088511

