/* $USAGI: extern.h,v 1.9 2001/01/27 04:14:53 yoshfuji Exp $ */

/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)extern.h	8.2 (Berkeley) 4/4/94
 *	NetBSD: extern.h,v 1.2 1995/04/11 02:44:49 cgd Exp
 *      $Id: extern.h,v 1.5 1999/07/16 01:12:54 dholland Exp $
 */

void	blkfree __P((char **));
char  **copyblk __P((char **));
void	cwd __P((const char *));
void	delete __P((char *));
void	dologout __P((int));
void	fatal __P((const char *));
int	ftpd_pclose __P((FILE *));
FILE   *ftpd_popen __P((char *, const char *));
char   *ftpd_getline __P((char *, int, FILE *));
void	ftpdlogwtmp __P((const char *, const char *, const char *));
void	lreply __P((int, const char *, ...));
void	makedir __P((char *));
void	nack __P((const char *));
void	pass __P((char *));
void	passive __P((void));
void	long_passive __P((const char *, int));
int	extended_port __P((const char *));
int	port_check __P((const char *));
int	port_check_v6 __P((const char *));
void	perror_reply __P((int, const char *));
void	pwd __P((void));
void	removedir __P((char *));
void	renamecmd __P((char *, char *));
char   *renamefrom __P((char *));
void	reply __P((int, const char *, ...));
void	retrieve __P((const char *, const char *));
void	send_file_list __P((const char *));
void	statcmd __P((void));
void	statfilecmd __P((char *));
void	store __P((const char *, const char *, int));
void	upper __P((char *));
void	user __P((char *));
void	yyerror __P((char *));
void	toolong __P((int));
int	yyparse __P((void));

struct utmp;
void login(const struct utmp *);
int logout(const char *line);

#ifdef __linux__
#include "daemon.h"
#include "setproctitle.h"
#endif

#include <netinet/in.h>

#ifdef HIP
#include <netdb.h>
#endif

union sockunion {
	struct sockinet {
#ifdef __linux__
		u_short	si_family;
#else
		u_char	si_len;
#define	su_len		su_si.si_len
		u_char	si_family;
#endif
		u_short	si_port;
	} su_si;
	struct	sockaddr		su_sa;
	struct	sockaddr_in		su_sin;
#ifdef HIP
	struct	sockaddr_eid		su_eid;
#endif
#ifdef INET6
	struct	sockaddr_in6		su_sin6;
#endif
};
#define	su_family	su_sa.sa_family
#define	su_port		su_si.si_port

#ifdef HIP
/* FIX ME*/
#elif INET6
#define ex_prot2af(p) (p == 1 ? AF_INET : (p == 2 ? AF_INET6 : -1))
#define ex_af2prot(a) (a == AF_INET ? 1 : (a == AF_INET6 ? 2 : 0))
#else
#define ex_prot2af(p) (p == 1 ? AF_INET : -1)
#define ex_af2prot(a) (a == AF_INET ? 1 : 0)
#endif
