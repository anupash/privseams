/* *****************************************************************
 *  base64.h
 *   © Copyright 1995 John Halleck
 *   All Rights Reserved
 *
 * --ABSTRACT--  base64.h
 * Do the base 64 encoding as used by PEM and MIME.
 *
 * --KEYWORDS--  base64.h
 *
 * --CONTENTS--  base64.h
 * Date, Department, Author
 *    23nov1994, John Halleck
 * Revision history
 *    For each revision: Date, change summary, authorizing document,
 *    change department, section, author
 *    23nov1994, Initial Creation, John Halleck
 *    8apr1995, split library into hex and base64 libraries, John Halleck
 * Unit purpose
 *    (What does this do?)
 *    [Nothing]
 * External Units accessed
 *    Name, purpose, access summary
 *    [None]
 * Exceptions propagated by this unit
 *    [None]
 * Machine-dependencies
 *    Access type, purpose, and justification
 *    [None]
 * Compiler-dependencies
 *    [None]
 ********************************************************************
 */

#ifndef  BASE64
#define  BASE64

#include "environ.h"
/* Defines common to everything */

#ifndef HEXB64FILTERS
#define HEXB64FILTERS
#ifdef NOPROTOTYPES
typedef void (*outroutine)();
typedef void (*inroutine)();
#else
/* output routine to process encoded characters */
typedef void (*outroutine)(char achar);
/* input routine to process decoded bytes */
typedef void (*inroutine)(BITS8 abyte);
#endif
/*prototypes*/
#endif
/*HEXB64FILTERS*/


/* Structure of a saved context */
typedef struct {
int temp;          /* Working value for input                */
int bytes;         /* which input byte we are working on     */
inroutine thisin;    /* Routine to call to process input byte  */
} b64incontext, *b64incontextptr;

typedef struct {
int temp;          /* Working value for output               */
int bytes;         /* which output byte we are working on    */
outroutine thisout;  /* Routine to call to process output byte */
} b64outcontext, *b64outcontextptr;

#ifndef NOPROTOTYPES


/* Base64 IO routines.
 *
 * Handing a routine a context pointer of NULL causes it to use a
 * single package wide canned context.
 *
 * Handing the initialization routine a NULL for IO routine causes it
 * to use standard IO.
 *
 *   So, For example, to put out a single byte in hex could be done as:
 *    Out64Init  (NULL, NULL); -- Initialize the package (to stdout)
 *    Out64      (NULL, 177);  -- output a hex byte
 *    Out64Flush (NULL);       -- Flush the output.
 */

/* Tests */
int Valid64 (char achar); /* Is this a valid base64 character? */

/* Hex output */
void Out64Init   (b64outcontextptr acontext, outroutine anout);
void Out64       (b64outcontextptr acontext, BITS8 abyte);
void Out64Flush  (b64outcontextptr acontext);

/* Hex input */
void In64Init   (b64incontextptr acontext, inroutine anin);
void In64       (b64incontextptr acontext, char abyte);
void In64Flush  (b64incontextptr acontext);

#else
/* We have no prototypes */

/* Tests */
int Valid64 (); /* Is this a valid base64 character? */

/* Hex output */
void Out64Init   ();
void Out64       ();
void Out64Flush  ();

/* Hex input */
void In64Init   ();
void In64       ();
void In64Flush  ();

#endif
/* no prototypes */


#endif
/*  BASE64 */
/* end  base64.h ***************************************************** */
