# Integer Overflow or Wraparound Vulnerability

## Description
If an integer expression involving an operation is compared to or assigned to a larger integer size, that integer expression should be evaluated in that larger size by explicitly casting one of the operands.

## Vulnerable Code Example
This code example is vulnerable on systems where ```size_t``` is an unsigned 32-bit value and long long is a 64-bit value. In this example, the developer tests for wrapping by comparing ```SIZE_MAX``` to length + ```BLOCK_HEADER_SIZE```. Because length is declared as size_t, the addition is performed as a 32-bit operation and can result in wrapping. The comparison with ```SIZE_MAX``` will always test false. If any wrapping occurs, ```malloc()``` will allocate insufficient space for mBlock, which can lead to a subsequent buffer overflow.

```c
#include <stdlib.h>
#include <stdint.h>  /* For SIZE_MAX */
  
enum { BLOCK_HEADER_SIZE = 16 };
 
void *AllocateBlock(size_t length) {
  struct memBlock *mBlock;
 
  if (length + BLOCK_HEADER_SIZE > (unsigned long long)SIZE_MAX)
    return NULL;
  mBlock = (struct memBlock *)malloc(
    length + BLOCK_HEADER_SIZE
  );
  if (!mBlock) { return NULL; }
  /* Fill in block header and return data portion */
 
  return mBlock;
}
```
## Mitigation 1

```c
#include <stdlib.h>
#include <stdint.h>
 
 
enum { BLOCK_HEADER_SIZE = 16 };
  
void *AllocateBlock(size_t length) {
  struct memBlock *mBlock;
 
  if ((unsigned long long)length + BLOCK_HEADER_SIZE > SIZE_MAX) {
    return NULL;
  }
  mBlock = (struct memBlock *)malloc(
    length + BLOCK_HEADER_SIZE
  );
  if (!mBlock) { return NULL; }
  /* Fill in block header and return data portion */
 
  return mBlock;
}
```
This test for wrapping is effective only when the sizeof(unsigned long long) > ```sizeof(size_t)```. If both ```size_t``` and unsigned long long types are represented as 64-bit unsigned values, the result of the addition operation may not be representable as an unsigned long long value.

## Mitigation 2
In this compliant solution, length is subtracted from ```SIZE_MAX```, ensuring that wrapping cannot occur.
```c
#include <stdlib.h>
#include <stdint.h>
  
enum { BLOCK_HEADER_SIZE = 16 };
 
void *AllocateBlock(size_t length) {
  struct memBlock *mBlock;
 
  if (SIZE_MAX - length < BLOCK_HEADER_SIZE) return NULL;
  mBlock = (struct memBlock *)malloc(
    length + BLOCK_HEADER_SIZE
  );
  if (!mBlock) { return NULL; }
  /* Fill in block header and return data portion */
 
  return mBlock;
}
```
## Vulnerable Code Example
In this vulnerable code example, the developer attempts to prevent wrapping by allocating an unsigned long long integer called alloc and assigning it the result from ```cBlocks * 16```:
```c

#include <stdlib.h>
#include <limits.h>
  
void *AllocBlocks(size_t cBlocks) {
  if (cBlocks == 0) { return NULL; }
  unsigned long long alloc = cBlocks * 16;
  return (alloc < UINT_MAX) ? malloc(cBlocks * 16) : NULL;
}
```
## Mitigation 
```c
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
  
static_assert(
  CHAR_BIT * sizeof(unsigned long long) >=
  CHAR_BIT * sizeof(size_t) + 4,
  "Unable to detect wrapping after multiplication"
);
 
void *AllocBlocks(size_t cBlocks) {
  if (cBlocks == 0) return NULL;
  unsigned long long alloc = (unsigned long long)cBlocks * 16;
  return (alloc < UINT_MAX) ? malloc(cBlocks * 16) : NULL;
}
```
Note that this code does not prevent wrapping unless the unsigned long long type is at least 4 bits larger than ```size_t```.


## Risk Assessment
Failure to cast integers before comparing or assigning them to a larger integer size can result in software vulnerabilities that can allow the execution of arbitrary code by an attacker with the permissions of the vulnerable process.

## References
* [CWE-190: Integer Overflow or Wraparound]
* [Programming Languages—C, 3rd ed (ISO/IEC 9899:2011). Geneva, Switzerland: ISO, 2011.]

[CWE-190: Integer Overflow or Wraparound]:https://cwe.mitre.org/data/definitions/190.html
[Programming Languages—C, 3rd ed (ISO/IEC 9899:2011). Geneva, Switzerland: ISO, 2011.]:https://wiki.sei.cmu.edu/confluence/display/c/AA.+Bibliography#AA.Bibliography-ISO-IEC9899-2011



