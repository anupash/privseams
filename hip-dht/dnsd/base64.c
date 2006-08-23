/* *****************************************************************
 *  base64.c
 * © Copyright 1994 John Halleck
 * All Rights Reserved
 *
 * --ABSTRACT--  base64.c
 * Do the base 64 encoding as used by PEM and MIME.
 *
 * --KEYWORDS--  base64.c
 *
 * --CONTENTS--  base64.c
 * Date, Department, Author
 *   23nov1994, John Halleck
 * Revision history
 *   For each revision: Date, change summary, authorizing document,
 *   change department, section, author
 *   23nov1994, Initial Creation, John Halleck
 * Unit purpose
 *   (What does this do?)
 *   [Nothing]
 * Unit function
 *   (How does it do it?)
 *   [Nothing]
 * External Units accessed
 *   Name, purpose, access summary
 * Exceptions propagated by this unit
 *   [None]
 * Input Output
 *   Device name, Access type, Access purpose, access summary
 *   [None]
 * Machine-dependencies
 *   Access type, purpose, and justification
 *   Assumes ASCII text.
 * Compiler-dependencies
 *   [None]
 *******************************************************************
 */

#include "environ.h"

#include "base64.h"
/* Public part of this unit. */

#include <stdio.h>

/* Availiable characters:
 * = character padding.
 * -*.,():; availiable for use...
 */

#ifndef NOPROTOTYPES
void getstdin  (BITS8 achar);  /* Put a character to standard out   */
void putstdout (char  achar);  /* Get a character from standard in  */
#endif

static char prtcode [] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static b64incontext incannedcontext; /* place for single thread input to be */
static b64outcontext outcannedcontext;

/* some standard routines for IO, if the user doesn't give one. */
/* -------------------------------------------------------- */
#ifndef NOPROTOTYPES
static void getstdin  (BITS8 achar) { putchar(achar); } /* Put a character to standard out   */
static void putstdout (char  achar) { putchar(achar); } /* Get a character from standard in  */
#else
static void getstdin  (achar) BITS8 achar; { putchar(achar); }
static void putstdout (achar) char achar;  { putchar(achar); }
#endif

/* -------------------------------------------------------- */

/* Tests */
#ifdef NOPROTOTYPES
int Valid64 (achar)
char achar;
#else
int Valid64 (char achar) /* Is this a valid hex character? */
#endif
{
  if (achar >= '0' && achar <= '9') return 1;
  if (achar >= 'a' && achar >= 'z') return 1;
  if (achar >= 'A' && achar >= 'Z') return 1;
  if (achar == '/') return 1;
  if (achar == '+') return 1;
  return 0;
}
/* -------------------------------------------------------- */

#ifdef NOPROTOTYPES
void In64Init (acontext, anin)
b64incontextptr acontext;
inroutine anin;
#else
void In64Init (b64incontextptr acontext, inroutine anin)
#endif
{
  if (!acontext) acontext = &incannedcontext;
  if (!anin)     anin     =  getstdin;
  acontext->bytes = 0;
  acontext->temp  = 0;
  acontext->thisin   = anin;
}

/* -------------------------------------------------------- */

#ifdef NOPROTOTYPES
void Out64Init (acontext, anout)
b64outcontextptr acontext;
outroutine anout;
#else
void Out64Init (b64outcontextptr acontext, outroutine anout)
#endif
{
  if (!acontext) acontext = &outcannedcontext;
  if (!anout)     anout   =  putstdout;
  acontext->bytes = 0;
  acontext->temp  = 0;
  acontext->thisout   = anout;
}

/* -------------------------------------------------------- */

#ifdef NOPROTOTYPES
void Out64   (acontext, abyte)
BITS8 abyte;
b64outcontextptr acontext;
{
#else
void Out64   (b64outcontextptr acontext, BITS8 abyte) {
#endif
  int result;
  if (!acontext) acontext = &outcannedcontext;
  if (!acontext->thisout) acontext->thisout = putstdout;

  /* Add this 8 bit byte to what we have...*/
  result = acontext->temp;
  result = (result << 8) | (abyte & 0xFF);

  /* And output all 6 bit base 64 characters now formed */
  switch (acontext->bytes++) {
    case 0: (*acontext->thisout)(prtcode[result>>2 & 0x3F]); result&= 0x3;
            break;
    case 1: (*acontext->thisout)(prtcode[result>>4 & 0x3F]); result&= 0xF;
            break;
    case 2: (*acontext->thisout)(prtcode[result>>6 & 0x3F]); 
            (*acontext->thisout)(prtcode[result    & 0x3F]);
            result = 0; acontext->bytes = 0;
  }
  acontext->temp = result;
}

/* -------------------------------------------------------- */

#ifdef NOPROTOTYPES
void In64 (acontext, achar)
char achar; b64incontextptr acontext;
{
#else
void In64 (b64incontextptr acontext, char achar) {
#endif
  int result;

  if (!acontext) acontext = &incannedcontext;
  if (!acontext->thisin) acontext->thisin = getstdin;
  result = acontext->temp;
  
  /* Convert Base64 character to its 6 bit nibble */
  if      (achar=='/')               result= (result<<6) | 63;
  else if (achar=='+')               result= (result<<6) | 62;
  else if (achar>='A' && achar<='Z') result= (result<<6) | (achar-'A');
  else if (achar>='a' && achar<='z') result= (result<<6) | (achar-'a'+26);
  else if (achar>='0' && achar<='9') result= (result<<6) | (achar-'0'+52);
  else if (achar == '=') { acontext->bytes=0;acontext->temp=0;}

  /* Add that nibble to the output, outputting any complete 8 bit bytes formed */
  switch (acontext->bytes++) {
    case 0: break;
    case 1: (*acontext->thisin) ((BITS8) (result>>4 & 0xFF)); result&=0xF;break;
    case 2: (*acontext->thisin) ((BITS8) (result>>2 & 0xFF)); result&=0x3;break; 
    case 3: (*acontext->thisin) ((BITS8) (result    & 0xFF));
             acontext->bytes = 0; result = 0;
  }
  if (achar == '=') {acontext->bytes = 0;result=0;}
  
  acontext->temp = result;
}

/* -------------------------------------------------------- */

#ifdef NOPROTOTYPES
void In64Flush (acontext)
b64incontextptr acontext; {
#else
void In64Flush (b64incontextptr acontext) {
#endif
 /* take care of the input side */
 /* Note that these are degenerate... no properly functioning
  * program would have handed these routines only part of the last byte.
  */
 /* Another byte will force the last nibble out */
 if (!acontext) acontext = &incannedcontext;
 if (acontext->bytes==1) (void) In64(acontext, 'A');
 acontext->bytes = 0;
 acontext->temp  = 0;
}

/* -------------------------------------------------------- */

#ifdef NOPROTOTYPES
void Out64Flush (acontext)
b64outcontextptr acontext; {
#else
void Out64Flush (b64outcontextptr acontext) {
#endif

 if (!acontext) acontext = &outcannedcontext;
 if (!acontext->thisout) acontext->thisout = putstdout;
 /* flush the output side of things, by putting out the last characters */
 switch (acontext->bytes) {
   case 0: break; /* nothing in progress */
   case 2: (*acontext->thisout)(prtcode[acontext->temp<<2 & 0x3F]);
           (*acontext->thisout)('=');
           break;
   case 1: (*acontext->thisout)(prtcode[acontext->temp<<4 & 0x3F]);
           (*acontext->thisout)('=');
           (*acontext->thisout)('=');
           break;
 } /* switch */
 acontext->bytes = 0;
 acontext->temp  = 0;
}

/*  base64.c **************************************************** */

