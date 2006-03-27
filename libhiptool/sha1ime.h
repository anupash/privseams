/*
 *  sha1ime.h
 *
 *  Description:
 *      This is the header file for code which implements the IME
 *      modification of Secure Hashing Algorithm 1 as defined in 
 *      FIPS PUB 180-1 and 180-2. 
 *
 *      Please read the file sha1ime.c for more information.
 *
 */

#ifndef _SHA1IME_H_
#define _SHA1IME_H_

#include <stdint.h>
/*
 * If you do not have the ISO standard stdint.h header file, then you
 * must typdef the following:
 *    name              meaning
 *  uint32_t         unsigned 32 bit integer
 *  uint8_t          unsigned 8 bit integer (i.e., unsigned char)
 *  int_least16_t    integer of >= 16 bits
 *
 */

#ifndef _SHA_enum_
#define _SHA_enum_
enum
{
    shaSuccess = 0,
    shaNull,            /* Null pointer parameter */
    shaInputTooLong,    /* input data too long */
    shaStateError       /* called Input after Result */
};
#endif
#define SHA1IMEHashSize 20

/*
 *  This structure will hold context information for the SHA-1
 *  hashing operation
 */
typedef struct SHA1IMEContext
{
    uint32_t Intermediate_Hash[SHA1IMEHashSize/4]; /* Message Digest  */

    uint32_t Length_Low;            /* Message length in bits      */
    uint32_t Length_High;           /* Message length in bits      */

                               /* Index into message block array   */
    int_least16_t Message_Block_Index;
    uint8_t Message_Block[64];      /* 512-bit message blocks      */

    int Computed;               /* Is the digest computed?         */
    int Corrupted;             /* Is the message digest corrupted? */
} SHA1IMEContext;

/*
 *  Function Prototypes
 */

int SHA1IMEReset(  SHA1IMEContext *);
int SHA1IMEInput(  SHA1IMEContext *,
                const uint8_t *,
                unsigned int);
int SHA1IMEResult( SHA1IMEContext *,
                uint8_t Message_Digest[SHA1IMEHashSize]);

#endif
