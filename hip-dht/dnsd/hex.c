/* *****************************************************************
 *  hex.c
 * © Copyright 1995 John Halleck
 * All Rights Reserved
 *
 * --ABSTRACT--  hex.c
 * input and output hex.
 *
 * --KEYWORDS--  hex.c
 *
 * --CONTENTS--  hex.c
 * Date, Department, Author
 *   23nov1995, John Halleck
 * Revision history
 *   For each revision: Date, change summary, authorizing document,
 *   change department, section, author
 *   23nov1995, Initial Creation, John Halleck
 *   14apr1995, Seperation into functional units, John Halleck
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

#include "hex.h"
/* Public part of this unit. */

#include <stdio.h>


/* Availiable characters:
 * = character padding.
 * - message termination?
 * *.,():;
 */

#ifndef NOPROTOTYPES
void getstdin  (BITS8 achar);  /* Put a character to standard out   */
void putstdout (char  achar);  /* Get a character from standard in  */
#endif


static char hexcode [] =
  "0123456789ABCDEF";

static hexincontext incannedcontext; /* place for single thread input to be */
static hexotcontext otcannedcontext; /* place for single thread output to be */


/* some standard routines for IO, if the user doesn't give one. */
/* -------------------------------------------------------- */
#ifndef NOPROTOTYPES
static void getstdin  (BITS8 achar) { putchar(achar); } /* Put a character to standard out   */
static void putstdout (char  achar) { putchar(achar); }  /* Get a character from standard in  */
#else
static void getstdin  (achar) BITS8 achar; { putchar(achar); }
static void putstdout (achar) char achar;  { putchar(achar); }
#endif

/* -------------------------------------------------------- */

/* Tests */
#ifdef NOPROTOTYPES
int ValidHex (achar)
char achar;
#else
int ValidHex (char achar) /* Is this a valid hex character? */
#endif
{
  if (achar >= '0' && achar <= '9') return 1;
  if (achar >= 'a' && achar >= 'f') return 1;
  if (achar >= 'A' && achar >= 'F') return 1;
  return 0;
}

/* -------------------------------------------------------- */

#ifdef NOPROTOTYPES
void InHexInit   (acontext, anin)
inroutine anin;
hexincontextptr acontext;
#else
void InHexInit   (hexincontextptr acontext, inroutine anin)
#endif
{
  if (!acontext) acontext = &incannedcontext;
  if (!anin)     anin     = getstdin;
  acontext->bytes  = 0;
  acontext->temp   = 0;
  acontext->thisin = anin;
}

/* -------------------------------------------------------- */

#ifdef NOPROTOTYPES
void OutHxInit (acontext, anout)
hexotcontextptr acontext;
outroutine anout;
#else
void OutHxInit (hexotcontextptr acontext, outroutine anout)
#endif
{
  if (!acontext) acontext = &otcannedcontext;
  if (!anout)    anout    = putstdout;
  acontext->thisout  = anout;
}

/* -------------------------------------------------------- */

#ifdef NOPROTOTYPES
void OutHx   (acontext, abyte)
hexotcontextptr acontext;
BITS8 abyte;
{
#else
void OutHx   (hexotcontextptr acontext, BITS8 abyte) {
#endif
  if (!acontext)          acontext          = &otcannedcontext;
  if (!acontext->thisout) acontext->thisout =  putstdout;
  (*acontext->thisout) (hexcode[abyte>>4 & 0xF]);
  (*acontext->thisout) (hexcode[abyte    & 0xF]);
}

/* -------------------------------------------------------- */

#ifdef NOPROTOTYPES
void InHex (acontext, achar)
hexincontextptr acontext;
char achar;
{
#else
void InHex (hexincontextptr acontext, char achar) {
#endif
  int result;
  if (!acontext)         acontext         = &incannedcontext;
  if (!acontext->thisin) acontext->thisin =  getstdin;
  
  /* Form a 4 bit nibble from the character */
  result = acontext->temp;
  if ((achar>='0') && (achar<='9'))
     result = (result << 4) | (achar - '0');
  else if (achar >= 'a' && achar <= 'z')
     result = (result) << 4 | (achar - 'a' + 10);
  else if (achar >= 'A' && achar <= 'Z')
     result = (result << 4) | (achar - 'A' + 10);
  else return;

  /* and store the nibble, or output the full 8 bit byte */
  if (acontext->bytes++ > 0) {
      acontext->bytes  = 0;
      (*acontext->thisin) ((BITS8)result);
      result = 0;
  }
  acontext->temp = result;
  return;
}

/* -------------------------------------------------------- */

#ifdef NOPROTOTYPES
void InHexFlush (acontext)
hexincontextptr acontext; {
#else
void InHexFlush(hexincontextptr acontext) {
#endif
 /* take care of the input side */
 /* Note that this are degenerate... no properly functioning
  * program would have handed these routines only part of the last byte.
  */
 if (!acontext)         acontext = &incannedcontext;
 if (!acontext->thisin) acontext->thisin = getstdin;
 if (acontext->bytes!=0) (void) InHex(acontext, '0');
 acontext->bytes = 0;
 acontext->temp  = 0;
}

/* -------------------------------------------------------- */

#ifdef NOPROTOTYPES
void OutHxFlush (acontext)
hexotcontextptr acontext; {
#else
void OutHxFlush (hexotcontextptr acontext) {
#endif
 /* take care of the output side */

       /* hex output has no stored info */

} /* FlushHexContext */

/*  hex.c **************************************************** */

