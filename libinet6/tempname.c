/* Copyright (C) 1991-1999, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#ifdef _USAGI_LIBINET6
#include "libc-compat.h"
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <assert.h>

/* Return nonzero if DIR is an existent directory.  */
static int
direxists (const char *dir)
{
  struct stat64 buf;
  return __xstat64 (_STAT_VER, dir, &buf) == 0 && S_ISDIR (buf.st_mode);
}

/* Path search algorithm, for tmpnam, tmpfile, etc.  If DIR is
   non-null and exists, uses it; otherwise uses the first of $TMPDIR,
   P_tmpdir, /tmp that exists.  Copies into TMPL a template suitable
   for use with mk[s]temp.  Will fail (-1) if DIR is non-null and
   doesn't exist, none of the searched dirs exists, or there's not
   enough space in TMPL. */
int
__path_search (char *tmpl, size_t tmpl_len, const char *dir, const char *pfx,
	       int try_tmpdir)
{
  const char *d;
  size_t dlen, plen;

  if (!pfx || !pfx[0])
    {
      pfx = "file";
      plen = 4;
    }
  else
    {
      plen = strlen (pfx);
      if (plen > 5)
	plen = 5;
    }

  if (try_tmpdir)
    {
      d = __secure_getenv ("TMPDIR");
      if (d != NULL && direxists (d))
	dir = d;
      else if (dir != NULL && direxists (dir))
	/* nothing */ ;
      else
	dir = NULL;
    }
  if (dir == NULL)
    {
      if (direxists (P_tmpdir))
	dir = P_tmpdir;
      else if (strcmp (P_tmpdir, "/tmp") != 0 && direxists ("/tmp"))
	dir = "/tmp";
      else
	{
	  __set_errno (ENOENT);
	  return -1;
	}
    }

  dlen = strlen (dir);
  while (dlen > 1 && dir[dlen - 1] == '/')
    dlen--;			/* remove trailing slashes */

  /* check we have room for "${dir}/${pfx}XXXXXX\0" */
  if (tmpl_len < dlen + 1 + plen + 6 + 1)
    {
      __set_errno (EINVAL);
      return -1;
    }

  sprintf (tmpl, "%.*s/%.*sXXXXXX", (int) dlen, dir, (int) plen, pfx);
  return 0;
}

/* These are the characters used in temporary filenames.  */
static const char letters[] =
"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* Generate a temporary file name based on TMPL.  TMPL must match the
   rules for mk[s]temp (i.e. end in "XXXXXX").  The name constructed
   does not exist at the time of the call to __gen_tempname.  TMPL is
   overwritten with the result.

   KIND may be one of:
   __GT_NOCREATE:	simply verify that the name does not exist
			at the time of the call.
   __GT_FILE:		create the file using open(O_CREAT|O_EXCL)
			and return a read-write fd.  The file is mode 0600.
   __GT_BIGFILE:	same as __GT_FILE but use open64().
   __GT_DIR:		create a directory, which will be mode 0700.

   We use a clever algorithm to get hard-to-predict names. */
int
__gen_tempname (char *tmpl, int kind)
{
  int len;
  char *XXXXXX;
  static uint64_t value;
  struct timeval tv;
  int count, fd = -1;
  int save_errno = errno;
  struct stat64 st;

  len = strlen (tmpl);
  if (len < 6 || strcmp (&tmpl[len - 6], "XXXXXX"))
    {
      __set_errno (EINVAL);
      return -1;
    }

  /* This is where the Xs start.  */
  XXXXXX = &tmpl[len - 6];

  /* Get some more or less random data.  */
  __gettimeofday (&tv, NULL);
  value += ((uint64_t) tv.tv_usec << 16) ^ tv.tv_sec ^ __getpid ();

  for (count = 0; count < TMP_MAX; value += 7777, ++count)
    {
      uint64_t v = value;

      /* Fill in the random bits.  */
      XXXXXX[0] = letters[v % 62];
      v /= 62;
      XXXXXX[1] = letters[v % 62];
      v /= 62;
      XXXXXX[2] = letters[v % 62];
      v /= 62;
      XXXXXX[3] = letters[v % 62];
      v /= 62;
      XXXXXX[4] = letters[v % 62];
      v /= 62;
      XXXXXX[5] = letters[v % 62];

      switch (kind)
	{
	case __GT_FILE:
	  fd = __open (tmpl, O_RDWR | O_CREAT | O_EXCL, 0600);
	  break;

	case __GT_BIGFILE:
	  fd = __open64 (tmpl, O_RDWR | O_CREAT | O_EXCL, 0600);
	  break;

	case __GT_DIR:
	  fd = __mkdir (tmpl, 0700);
	  break;

	case __GT_NOCREATE:
	  /* This case is backward from the other three.  __gen_tempname
	     succeeds if __xstat fails because the name does not exist.
	     Note the continue to bypass the common logic at the bottom
	     of the loop.  */
	  if (__lxstat64 (_STAT_VER, tmpl, &st) < 0)
	    {
	      if (errno == ENOENT)
		{
		  __set_errno (save_errno);
		  return 0;
		}
	      else
		/* Give up now. */
		return -1;
	    }
	  continue;

	default:
	  HIP_ASSERT (! "invalid KIND in __gen_tempname");
	}

      if (fd >= 0)
	{
	  __set_errno (save_errno);
	  return fd;
	}
      else if (errno != EEXIST)
	return -1;
    }

  /* We got out of the loop because we ran out of combinations to try.  */
  __set_errno (EEXIST);
  return -1;
}
