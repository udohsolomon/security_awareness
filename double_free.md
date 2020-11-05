# Double-Free Vulnerability

## Description
Allocating and freeing memory in different modules and levels of abstraction may make it difficult to determine when and if a block of memory has been freed, leading to programming defects, such as double-free vulnerabilities. When a program calls free() twice with the same argument, the program's memory management data structures become corrupted. This corruption can cause the program to crash or, in some circumstances, cause two later calls to ```malloc()``` to return the same pointer. If ```malloc()``` returns the same value twice and the program later gives the attacker control over the data that is written into this doubly-allocated memory, the program becomes vulnerable to a buffer overflow attack.

To avoid this situation, memory should be allocated and freed at the same level of abstraction and, ideally, in the same code module. This includes the use of the following memory allocation and deallocation functions described in subclause.

## Vulnerable Code Example
This noncompliant code example shows a double-free vulnerability resulting from memory being allocated and freed at differing levels of abstraction. In this example, memory for the list array is allocated in the ```process_list()``` function. The array is then passed to the ```verify_size()``` function that performs error checking on the size of the list. If the size of the list is below a minimum size, the memory allocated to the list is freed, and the function returns to the caller. The calling function then frees this same memory again, resulting in a double-free and potentially exploitable vulnerability.

```c
enum { MIN_SIZE_ALLOWED = 32 };
 
int verify_size(char *list, size_t size) {
  if (size < MIN_SIZE_ALLOWED) {
    /* Handle error condition */
    free(list);
    return -1;
  }
  return 0;
}
 
void process_list(size_t number) {
  char *list = (char *)malloc(number);
  if (list == NULL) {
    /* Handle allocation error */
  }
 
  if (verify_size(list, number) == -1) {
      free(list);
      return;
  }
 
  /* Continue processing list */
 
  free(list);
}
```

The call to free memory in the ```verify_size()``` function takes place in a subroutine of the ```process_list()``` function, at a different level of abstraction from the allocation, resulting in a violation of this recommendation. The memory deallocation also occurs in error-handling code, which is frequently not as well tested as "green paths" through the code.

## Mitigation
To correct this problem, the error-handling code in ```verify_size()``` is modified so that it no longer frees list. This change ensures that list is freed only once, at the same level of abstraction, in the ```process_list()``` function.

```c
enum { MIN_SIZE_ALLOWED = 32 };
 
int verify_size(const char *list, size_t size) {
  if (size < MIN_SIZE_ALLOWED) {
    /* Handle error condition */
    return -1;
  }
  return 0;
}
 
void process_list(size_t number) {
  char *list = (char *)malloc(number);
 
  if (list == NULL) {
    /* Handle allocation error */
  }
 
  if (verify_size(list, number) == -1) {
      free(list);
      return;
  }
 
  /* Continue processing list */
 
  free(list);
}
```

## Risk Assessment
The mismanagement of memory can lead to freeing memory multiple times or writing to already freed memory. Both of these coding errors can result in an attacker executing arbitrary code with the permissions of the vulnerable process. Memory management errors can also lead to resource depletion and denial-of-service attacks.

## References
* [CWE-415: Double Free]
* [Programming Languages—C, 3rd ed (ISO/IEC 9899:2011). Geneva, Switzerland: ISO, 2011.]

[CWE-415: Double Free]:https://cwe.mitre.org/data/definitions/415.html
[Programming Languages—C, 3rd ed (ISO/IEC 9899:2011). Geneva, Switzerland: ISO, 2011.]:https://wiki.sei.cmu.edu/confluence/display/c/AA.+Bibliography#AA.Bibliography-ISO-IEC9899-2011
