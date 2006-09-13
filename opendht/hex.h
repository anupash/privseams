/* *****************************************************************
 *  hex.h
 *   © Copyright 1995 John Halleck
 *   All Rights Reserved
 *
 * --ABSTRACT--  hex.h
 * input and output hex.
 *
 * --KEYWORDS--  hex.h
 *
 * --CONTENTS--  hex.h
 * Date, Department, Author
 *    23nov1994, John Halleck
 * Revision history
 *    For each revision: Date, change summary, authorizing document,
 *    change department, section, author
 *    23nov1994, Initial Creation, John Halleck
 *    14apr1995, Split into functional units, John Halleck
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

#ifndef  HEX
#define  HEX

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


/* Working context for input routines */
typedef struct {
   outroutine thisout;  /* Routine to call to process output byte */
} hexotcontext, *hexotcontextptr;

/* Working context for input routines */
typedef struct {
   int temp;            /* Working value for input                */
   int bytes;           /* which input byte we are working on     */
   inroutine thisin;    /* Routine to call to process input byte  */
} hexincontext, *hexincontextptr;

#ifndef NOPROTOTYPES


/* Hex IO routines.
 *
 * Handing a routine a context pointer of NULL causes it to use a
 * single package wide canned context.
 *
 * Handing the initialization routine a NULL for IO routine causes it
 * to use standard IO.
 *
 *   So, For example, to put out a single byte in hex could be done as:
 *    OutHxInit  (NULL, NULL); -- Initialize the package (to stdout)
 *    OutHx      (NULL, 177);  -- output a hex byte
 *    OutHxFlush (NULL);       -- Flush the output.
 */

/* Tests */
int ValidHex (char achar); /* Is this a valid hex character? */

/* Hex output */
void OutHxInit   (hexotcontextptr acontext, outroutine anout);
void OutHx       (hexotcontextptr acontext, BITS8 abyte);
void OutHxFlush  (hexotcontextptr acontext);

/* Hex input */
void InHexInit   (hexincontextptr acontext, inroutine anin);
void InHex       (hexincontextptr acontext, char abyte);
void InHexFlush  (hexincontextptr acontext);

#else
/* No prototypes */

/* Tests */
int ValidHex (); /* Is this a valid hex character? */

/* Hex output */
void OutHxInit   ();
void OutHx       ();
void OutHxFlush  ();

/* Hex output */
void InHexInit   ();
void InHex       ();
void InHexFlush  ();

#endif
/*noprototypes*/


#endif
/*  hex */
/* end  hex.h ***************************************************** */
