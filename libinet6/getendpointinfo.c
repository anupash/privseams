/*
 * getendpointinfo: native HIP API resolver
 *
 * Author:    Miika Komu <miika@iki.fi>
 * Copyright: Miika Komu 2004, The Inner Net License v2.00.
 * Notes:     This library uses the code in this directory from Craig Metz.
 *
 * Todo:
 * - Move the association functions to their own files when you find better
 *   names for them.
 * Bugs:
 * - xx
 */

/* The Inner Net License, Version 2.00

  The author(s) grant permission for redistribution and use in source and
binary forms, with or without modification, of the software and documentation
provided that the following conditions are met:

0. If you receive a version of the software that is specifically labelled
   as not being for redistribution (check the version message and/or README),
   you are not permitted to redistribute that version of the software in any
   way or form.
1. All terms of the all other applicable copyrights and licenses must be
   followed.
2. Redistributions of source code must retain the authors' copyright
   notice(s), this list of conditions, and the following disclaimer.
3. Redistributions in binary form must reproduce the authors' copyright
   notice(s), this list of conditions, and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
4. All advertising materials mentioning features or use of this software
   must display the following acknowledgement with the name(s) of the
   authors as specified in the copyright notice(s) substituted where
   indicated:

	This product includes software developed by <name(s)>, The Inner
	Net, and other contributors.

5. Neither the name(s) of the author(s) nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY ITS AUTHORS AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

  If these license terms cause you a real problem, contact the author.  */

#ifdef _USAGI_LIBINET6
#include "libc-compat.h"
#endif

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <net/if.h>

#include <ctype.h>
#include "linux/hip_ioctl.h"
#include "builder.h"

int setmyeid(int sockfd, struct sockaddr_eid *myeid, struct endpoint *endpoint,
	     struct if_nameindex *ifaces)
{
  HIP_DEBUG("\n");
  return 0;
}

int setpeereid(struct sockaddr_eid *peereid, struct endpoint *endpoint,
	       struct addrinfo *addrlist)
{
  HIP_DEBUG("\n");
  return 0;
}

#if 0
//XX FIXME
void gethosts_hi(char *_name)
 {
  struct in6_addr hit;
  FILE *fp = NULL;
  char fqdn_str[255+1];
  char hit_str[INET6_ADDRSTRLEN+1];
  int lineno = 1;

  /* TODO: check return values */
  fp = fopen(_PATH_HIP_HOSTS, "r");
  if(!fp)
    goto _get_hosts_hit_out;

  while (1) {
    int c;
    int ret;
    memset(fqdn_str, 0, sizeof(fqdn_str));
    memset(hit_str, 0, sizeof(hit_str));
    ret = fscanf(fp, "%46s %255s", hit_str, fqdn_str);
    if (ret == 2) {
      _HIP_DEBUG("line %d hit=%s fqdn=%s\n", lineno, hit_str, fqdn_str);
      if (inet_pton(AF_INET6, hit_str, &hit) <= 0) {
	HIP_DEBUG("hiphosts invalid hit\n");
        goto _get_hosts_hit_out;
      }
      if ((strlen(_name) == strlen(fqdn_str)) &&
	  strcmp(_name, fqdn_str) == 0) {
	_HIP_DEBUG("** match on line %d **\n", lineno);
	found_hits = 1;
	if (*pat == NULL) {
	  *pat = __alloca(sizeof(struct gaih_addrtuple));
	  (*pat)->scopeid = 0;
	}
	(*pat)->next = NULL;
	(*pat)->family = AF_INET6;
	memcpy((*pat)->addr, &hit, sizeof(struct in6_addr));
	pat = &((*pat)->next);
      }
    } else if (ret == EOF) {
      _HIP_DEBUG("hiphosts EOF on line %d\n", lineno);
      goto _get_hosts_hit_out;
    } else {
      HIP_DEBUG("hiphosts fscanf ret != 2 on line %d\n", lineno);
      goto _get_hosts_hit_out;
    }

    lineno++;
  }
 _get_hosts_hit_out:
  if (fp)
    fclose(fp);
 }
#endif

int getendpointinfo(const char *nodename, const char *servname,
		    const struct endpointinfo *hints,
		    struct endpointinfo **res)
{
  int err = 0;
  struct addrinfo *ai_res = &(*res)->ei_addrlist;

  HIP_DEBUG("\n");
  err = getaddrinfo(nodename, servname, &hints->ei_addrlist,
		    &ai_res);

  return err;
}

void free_endpointinfo(struct endpointinfo *res)
{
  freeaddrinfo(&res->ei_addrlist);
  HIP_DEBUG("\n");
}

const char *gepi_strerror(int errcode)
{
  HIP_DEBUG("\n");
  return "gepi unimplemented";
}
