/* $USAGI: getaddrinfo.c,v 1.10 2003/01/07 10:22:52 yoshfuji Exp $ */

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

/* This software is Copyright 1996 by Craig Metz, All Rights Reserved.  */

#ifdef _USAGI_LIBINET6
#include "libc-compat.h"
#endif

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
#include "builder.h"
#include "debug.h"
#include "message.h"
#include "util.h"
#include "libhipopendht.h"

/*
#ifdef CONFIG_HIP_OPENDHT
#include "dhtresolver.h"
#endif
*/

#include "bos.h"

#define GAIH_OKIFUNSPEC 0x0100
#define GAIH_EAI        ~(GAIH_OKIFUNSPEC)

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX  108
#endif

#ifndef NUM_MAX_HITS
#define NUM_MAX_HITS 50
#endif

// extern u32 opportunistic_mode;
struct gaih_service
  {
    const char *name;
    int num;
  };

struct gaih_servtuple
  {
    struct gaih_servtuple *next;
    int socktype;
    int protocol;
    int port;
  };

static const struct gaih_servtuple nullserv;

/* Moved to util.h, used in getendpointinfo.c
struct gaih_addrtuple
  {
    struct gaih_addrtuple *next;
    int family;
    char addr[16];
    uint32_t scopeid;
  };
*/

struct gaih_typeproto
  {
    int socktype;
    int protocol;
    char name[4];
    int protoflag;
  };

/* Values for `protoflag'.  */
#define GAI_PROTO_NOSERVICE	1
#define GAI_PROTO_PROTOANY	2

static const struct gaih_typeproto gaih_inet_typeproto[] =
{
  { 0, 0, "", 0 },
  { SOCK_STREAM, IPPROTO_TCP, "tcp", 0 },
  { SOCK_DGRAM, IPPROTO_UDP, "udp", 0 },
  { SOCK_RAW, 0, "raw", GAI_PROTO_PROTOANY|GAI_PROTO_NOSERVICE },
  { 0, 0, "", 0 }
};

struct gaih
  {
    int family;
    int (*gaih)(const char *name, const struct gaih_service *service,
		const struct addrinfo *req, struct addrinfo **pai,
		int hip_transparent_mode);
  };

#if PF_UNSPEC == 0
static const struct addrinfo default_hints;
#else
static const struct addrinfo default_hints =
	{ 0, PF_UNSPEC, 0, 0, 0, NULL, NULL, NULL };
#endif

static int addrconfig (sa_family_t af)
{
  int s;
  int ret;
  int saved_errno = errno;

  _HIP_DEBUG("af=%d", af);
  
  s = socket(af, SOCK_DGRAM, 0);
  if (s < 0)
    ret = (errno == EMFILE) ? 1 : 0;
  else
    {
      close(s);
      ret = 1;
    }
  __set_errno (saved_errno);
  return ret;
}

void free_gaih_servtuple(struct gaih_servtuple *tuple) {
  struct gaih_servtuple *tmp;

  while(tuple) {
    tmp = tuple;
    tuple = tmp->next;
    free(tmp);
  }
}

void dump_pai (struct gaih_addrtuple *at)
{
  struct gaih_addrtuple *a;

  if (at == NULL)
    HIP_DEBUG("dump_pai: input NULL!\n");
  
  for(a = at; a != NULL; a = a->next) {        
    //HIP_DEBUG("scope_id=%lu\n", (long unsigned int)ai->scopeid);
    if (a->family == AF_INET6) {
      struct in6_addr *s = (struct in6_addr *)a->addr;
      int i = 0;
      HIP_DEBUG("AF_INET6\tin6_addr=0x");
      for (i = 0; i < 16; i++)
	HIP_DEBUG("%02x", (unsigned char) (s->in6_u.u6_addr8[i]));
      HIP_DEBUG("\n");
    } else if (a->family == AF_INET) {
      struct in_addr *s = (struct in_addr *)a->addr;
      long unsigned int ad = ntohl(s->s_addr);
      HIP_DEBUG("AF_INET\tin_addr=0x%lx (%s)\n", ad, inet_ntoa(*s));
    } else 
      HIP_DEBUG("Unknown family\n");
 }
}

static int
gaih_local (const char *name, const struct gaih_service *service,
	    const struct addrinfo *req, struct addrinfo **pai, int unused)
{
  struct utsname utsname;

  if (service)
    _HIP_DEBUG("name='%s' service->name='%s' service->num=%d\n", name, 
               service->name, service->num);
  else
    _HIP_DEBUG("name='%s'\n", name);

  _HIP_DEBUG("req:ai_flags=0x%x ai_family=%d ai_socktype=%d ai_protocol=%d\n\n", req->ai_flags, req->ai_family, req->ai_socktype, req->ai_protocol);
  if (*pai)
    _HIP_DEBUG("pai:ai_flags=0x%x ai_family=%d ai_socktype=%d ai_protocol=%d\n\n", (*pai)->ai_flags, (*pai)->ai_family, (*pai)->ai_socktype, (*pai)->ai_protocol);

  if ((name != NULL) && (req->ai_flags & AI_NUMERICHOST))
    return GAIH_OKIFUNSPEC | -EAI_NONAME;

  if ((name != NULL) || (req->ai_flags & AI_CANONNAME))
    if (uname (&utsname) < 0)
      return -EAI_SYSTEM;

  if (name != NULL)
    {
      if (strcmp(name, "localhost") &&
	  strcmp(name, "local") &&
	  strcmp(name, "unix") &&
	  strcmp(name, utsname.nodename))
	return GAIH_OKIFUNSPEC | -EAI_NONAME;
    }

  if (req->ai_protocol || req->ai_socktype)
    {
      const struct gaih_typeproto *tp = gaih_inet_typeproto + 1;

      while (tp->name[0]
	     && ((tp->protoflag & GAI_PROTO_NOSERVICE) != 0
		 || (req->ai_socktype != 0 && req->ai_socktype != tp->socktype)
		 || (req->ai_protocol != 0
		     && !(tp->protoflag & GAI_PROTO_PROTOANY)
		     && req->ai_protocol != tp->protocol)))
	++tp;

      if (! tp->name[0])
	{
	  if (req->ai_socktype)
	    return (GAIH_OKIFUNSPEC | -EAI_SOCKTYPE);
	  else
	    return (GAIH_OKIFUNSPEC | -EAI_SERVICE);
	}
    }

  *pai = malloc (sizeof (struct addrinfo) + sizeof (struct sockaddr_un)
		 + ((req->ai_flags & AI_CANONNAME)
		    ? (strlen(utsname.nodename) + 1): 0));
  if (*pai == NULL)
    return -EAI_MEMORY;

  (*pai)->ai_next = NULL;
  (*pai)->ai_flags = req->ai_flags;
  (*pai)->ai_family = AF_LOCAL;
  (*pai)->ai_socktype = req->ai_socktype ? req->ai_socktype : SOCK_STREAM;
  (*pai)->ai_protocol = req->ai_protocol;
  (*pai)->ai_addrlen = sizeof (struct sockaddr_un);
  (*pai)->ai_addr = (void *) (*pai) + sizeof (struct addrinfo);
#ifdef _HAVE_SA_LEN
  ((struct sockaddr_un *) (*pai)->ai_addr)->sun_len =
    sizeof (struct sockaddr_un);
#endif /* _HAVE_SA_LEN */
  ((struct sockaddr_un *)(*pai)->ai_addr)->sun_family = AF_LOCAL;
  memset(((struct sockaddr_un *)(*pai)->ai_addr)->sun_path, 0, UNIX_PATH_MAX);

  if (service)
    {
      struct sockaddr_un *sunp = (struct sockaddr_un *) (*pai)->ai_addr;

      if (strchr (service->name, '/') != NULL)
	{
	  if (strlen (service->name) >= sizeof (sunp->sun_path))
	    return GAIH_OKIFUNSPEC | -EAI_SERVICE;

	  strcpy (sunp->sun_path, service->name);
	}
      else
	{
	  if (strlen (P_tmpdir "/") + 1 + strlen (service->name) >=
	      sizeof (sunp->sun_path))
	    return GAIH_OKIFUNSPEC | -EAI_SERVICE;

	  __stpcpy (__stpcpy (sunp->sun_path, P_tmpdir "/"), service->name);
	}
    }
  else
    {
      /* This is a dangerous use of the interface since there is a time
	 window between the test for the file and the actual creation
	 (done by the caller) in which a file with the same name could
	 be created.  */
      char *buf = ((struct sockaddr_un *) (*pai)->ai_addr)->sun_path;

      if (__builtin_expect (__path_search (buf, L_tmpnam, NULL, NULL, 0),
			    0) != 0
	  || __builtin_expect (__gen_tempname (buf, __GT_NOCREATE), 0) != 0)
	return -EAI_SYSTEM;
    }

  if (req->ai_flags & AI_CANONNAME)
    (*pai)->ai_canonname = strcpy ((char *) *pai + sizeof (struct addrinfo)
				   + sizeof (struct sockaddr_un),
				   utsname.nodename);
  else
    (*pai)->ai_canonname = NULL;
  return 0;
}

static int
gaih_inet_serv (const char *servicename, const struct gaih_typeproto *tp,
	       const struct addrinfo *req, struct gaih_servtuple *st)
{
  struct servent *s;
  size_t tmpbuflen = 1024;
  struct servent ts;
  char *tmpbuf;
  int r;

  if (tp)
    _HIP_DEBUG("servicename='%s' tp->socktype=%d tp->protocol=%d tp->name=%s tp->protoflag=%d\n", servicename, tp->socktype, tp->protocol, tp->name, tp->protoflag);
  else 
    _HIP_DEBUG("servicename='%s' tp=NULL\n", servicename);

  _HIP_DEBUG("req:ai_flags=0x%x ai_family=%d ai_socktype=%d ai_protocol=%d\n", req->ai_flags, req->ai_family, req->ai_socktype, req->ai_protocol);
  if (st)
    _HIP_DEBUG("st:socktype=%d protocol=%d port=%d\n", st->socktype, st->protocol, st->port);

  do
    {
      tmpbuf = __alloca (tmpbuflen);

      r = __getservbyname_r (servicename, tp->name, &ts, tmpbuf, tmpbuflen,
			     &s);
      if (r != 0 || s == NULL)
	{
	  if (r == ERANGE)
	    tmpbuflen *= 2;
	  else
	    return GAIH_OKIFUNSPEC | -EAI_SERVICE;
	}
    }
  while (r);

  st->next = NULL;
  st->socktype = tp->socktype;
  st->protocol = ((tp->protoflag & GAI_PROTO_PROTOANY)
		  ? req->ai_protocol : tp->protocol);
  st->port = s->s_port;

  return 0;
}

int 
gethosts(const char *name, int _family, 
		 struct gaih_addrtuple ***pat) 
 {								
  int i, herrno;						
  size_t tmpbuflen = 512;					       
  struct hostent th;						
  char *tmpbuf;							
  int no_data = 0;							
  int rc = 0;
  struct hostent *h = NULL;
  struct gaih_addrtuple *aux = NULL;

  /* freeing the already allocated structure if it si empty
     Warning: Not good practice, may cause problems */
  if(**pat != NULL && (**pat)->next == NULL && (**pat)->family == 0){
    free(**pat);
    **pat = NULL;
  }

  do {								
    tmpbuflen *= 2;						
    tmpbuf = __alloca (tmpbuflen);				
    rc = __gethostbyname2_r (name, _family, &th, tmpbuf,	
         tmpbuflen, &h, &herrno);				
  } while (rc == ERANGE && herrno == NETDB_INTERNAL);		
  if (rc != 0)							
    {								
      if (herrno == NETDB_INTERNAL)				
	{							
	  __set_h_errno (herrno);				
	  return -EAI_SYSTEM;					
	}							
      if (herrno == TRY_AGAIN)					
	no_data = EAI_AGAIN;					
      else							
	no_data = herrno == NO_DATA;				
    }								
  else if (h != NULL)						
    {
      for (i = 0; h->h_addr_list[i]; i++)			
	{
	  if ((aux = (struct gaih_addrtuple *) malloc(sizeof(struct gaih_addrtuple))) == NULL){
	    HIP_ERROR("Memory allocation error\n");
	    exit(-EAI_MEMORY);
	  }
	  //Placing the node at the beginning of the list
	  aux->next = (**pat);
	  (**pat) = aux;
	  aux->scopeid = 0;    					
	  aux->family = _family;				
	  memcpy (aux->addr, h->h_addr_list[i],		
		 (_family == AF_INET6)
		  ? sizeof(struct in6_addr)
		  : sizeof(struct in_addr));					
	}								
    }								
  return no_data;
 }

int 
gethosts_hit(const char * name, struct gaih_addrtuple ***pat, int flags)
 {									
  struct in6_addr hit;							
  FILE *fp = NULL;							
  char *fqdn_str;                                                       
  char *hit_str;                                                        
  int lineno = 0, i=0;                                                  
  char line[500];							
  List list;
  int found_hits = 0;
  struct gaih_addrtuple *aux = NULL;

#ifdef CONFIG_HIP_OPENDHT
 
  int s, error, ret_hit, ret_addr;
  char dht_response_hit[1024];
  char dht_response_addr[1024];
  struct in6_addr tmp_hit, tmp_addr;
  struct addrinfo * serving_gateway;
  char ownaddr[] = "127.0.0.1";

  /*
  struct hip_common *msg;
  struct hip_opendht_gw_info *gw_info;
  struct in_addr tmp_v4;
  char tmp_ip_str[21];
  int tmp_ttl, tmp_port;
  int *pret;
  int err;
  */

  if (flags & AI_NODHT)
    goto skip_dht;

  memset(dht_response_hit, '\0', sizeof(dht_response_hit));
  memset(dht_response_addr, '\0', sizeof(dht_response_addr));

  ret_hit = -1;  
  ret_addr = -1;

  /* ask about the serving gateway from the daemon */
  
  //  HIP_DEBUG("Asking serving gateway info from daemon...\n");
  /*
  HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, "Malloc for msg failed\n");
  HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DHT_SERVING_GW,0),-1, 
           "Building daemon header failed\n"); 
  HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "Send recv daemon info failed\n");
  HIP_IFEL(!(gw_info = hip_get_param(msg, HIP_PARAM_OPENDHT_GW_INFO)),-1, 
           "No gw struct found\n");
  memset(&tmp_ip_str,'\0',20);
  tmp_ttl = gw_info->ttl;
  tmp_port = htons(gw_info->port);
  IPV6_TO_IPV4_MAP(&gw_info->addr, &tmp_v4);
  pret = inet_ntop(AF_INET, &tmp_v4, tmp_ip_str, 20);
  HIP_DEBUG("Got address %s, port %d, TTL %d from daemon\n",
            tmp_ip_str, tmp_port, tmp_ttl);

 out_err:
  HIP_DEBUG("OUT ERROROROROROR\n");      
  */

  s = init_dht_gateway_socket(s);
  if (s < 0) 
  {
    HIP_DEBUG("Socket creation for openDHT failed skipping openDHT\n");
    goto skip_dht;
  }
  error = 0;
  error = resolve_dht_gateway_info ("opendht.nyuld.net", &serving_gateway);
  if (error < 0)
  {
    HIP_DEBUG("Error in  resolving the openDHT gateway address, skipping openDHT\n");
    close(s);
    goto skip_dht;
  }
  error = 0;
  error = connect_dht_gateway(s, serving_gateway, 1);
  if (error < 0)
  {
    HIP_DEBUG("Error on connect to openDHT gateway, skipping openDHT\n");
    close(s);
    goto skip_dht;
  }
  ret_hit = opendht_get(s, (unsigned char *)name, (unsigned char *)ownaddr, 5851);
  ret_hit = opendht_read_response(s, dht_response_hit);
  if (ret_hit == 0)
    HIP_DEBUG("HIT received from DHT: %s\n", dht_response_hit);
  close(s);
  if (ret_hit == 0 && (strlen((char *)dht_response_hit) > 1))
  {
    s = init_dht_gateway_socket(s);
    error = connect_dht_gateway(s, &serving_gateway, 1);
    if (error < 0)
    {
      HIP_DEBUG("Error on connect to openDHT gateway, skipping openDHT\n");
      goto skip_dht;
    }
    ret_addr = opendht_get(s, (unsigned char *)dht_response_hit, (unsigned char *)ownaddr, 5851);
    ret_addr = opendht_read_response(s, dht_response_addr);
    if (ret_addr == 0)
      HIP_DEBUG("Address received from DHT: %s\n",dht_response_addr);
    close(s);
  }
  if ((ret_hit == 0) && (ret_addr == 0) && 
      (dht_response_hit[0] != '\0') && (dht_response_addr[0] != '\0')) 
    { 

      if (inet_pton(AF_INET6, dht_response_hit, &tmp_hit) >0 &&
          inet_pton(AF_INET6, dht_response_addr, &tmp_addr) >0) {

	if (**pat == NULL) {						
	  if ((**pat = (struct gaih_addrtuple *) malloc(sizeof(struct gaih_addrtuple))) == NULL){
	    HIP_ERROR("Memory allocation error\n");
	    exit(-EAI_MEMORY);
	  }	  
	  (**pat)->scopeid = 0;				
	}
	(**pat)->family = AF_INET6;					
	memcpy((**pat)->addr, &tmp_hit, sizeof(struct in6_addr));		
	*pat = &((**pat)->next);				     	
	
	if ((**pat = (struct gaih_addrtuple *) malloc(sizeof(struct gaih_addrtuple))) == NULL){
	  HIP_ERROR("Memory allocation error\n");
	  exit(-EAI_MEMORY);
	}	  

	(**pat)->scopeid = 0;				
	(**pat)->next = NULL;						
	(**pat)->family = AF_INET6;					
	memcpy((**pat)->addr, &tmp_addr, sizeof(struct in6_addr));	
	*pat = &((**pat)->next);
        /* dump_pai(*pat); */
	return 1;
      }
    } 
  /* CONFIG_HIP_OPENDHT */
 skip_dht:
#endif
									
  /*! \todo check return values */
  _HIP_DEBUG("Opening %s\n", _PATH_HIP_HOSTS);
  fp = fopen(_PATH_HIP_HOSTS, "r");		
								
  while (fp && getwithoutnewline(line, 500, fp) != NULL) {		
    int c;								
    int ret;
                                                            
    lineno++;								
    if(strlen(line)<=1) continue;                                       
    initlist(&list);                                                    
    extractsubstrings(line,&list);                                      
    for(i=0;i<length(&list);i++) {                                      
      if (inet_pton(AF_INET6, getitem(&list,i), &hit) <= 0) {		
	fqdn_str = getitem(&list,i);	               		        
      }                                                                 
    }									
    if ((strlen(name) == strlen(fqdn_str)) &&		         	
      strcmp(name, fqdn_str) == 0) {				        
      _HIP_DEBUG("** match on line %d **\n", lineno);			
      found_hits = 1; 
                                                                        
      /* add every HIT to linked list */				
      for(i=0;i<length(&list);i++) {                                    
	uint32_t lsi = htonl(HIT2LSI((uint8_t *) &hit));	
	struct gaih_addrtuple *prev_pat = NULL;	
	_HIP_DEBUG("hit: %x  getitem(&list,i): %s \n", hit, getitem(&list,i));
        ret = inet_pton(AF_INET6, getitem(&list,i), &hit);
	_HIP_DEBUG("hit: %x\n", hit);              
        if (ret < 1) continue;         
 
	if ((aux = (struct gaih_addrtuple *) malloc(sizeof(struct gaih_addrtuple))) == NULL){
	  HIP_ERROR("Memory allocation error\n");
	  exit(-EAI_MEMORY);
	}

	//Placing the node at the beginning of the list
	aux->next = (**pat);
	(**pat) = aux;
	aux->scopeid = 0;				
	aux->family = AF_INET6;
	memcpy(aux->addr, &hit, sizeof(struct in6_addr));

#if 0 /* Disabled as this is not support by the daemon yet -miika*/
	/* AG: add LSI as well */					
        if (**pat == NULL) {
	  if ((**pat = (struct gaih_addrtuple *) malloc(sizeof(struct gaih_addrtuple))) == NULL){
	    HIP_ERROR("Memory allocation error\n");
	    exit(-EAI_MEMORY);
	  }

	  (**pat)->scopeid = 0;				
        }								
        (**pat)->next = NULL;						
        (**pat)->family = AF_INET;					
        memcpy((**pat)->addr, &lsi, sizeof(hip_lsi_t));			
        *pat = &((**pat)->next);					      
#endif
      }									
    } // end of if 

    destroy(&list);                                                     
  } // end of while	              							
  if (fp)                                                               
    fclose(fp);		
  return found_hits;	        				
}


/* perform HIT-IPv6 mapping if both are found 
	     AG: now the loop also takes in IPv4 addresses */
void 
send_hipd_addr(struct gaih_addrtuple * orig_at)
{
  struct gaih_addrtuple *at_ip, *at_hit;
  struct hip_common *msg;
  msg = malloc(HIP_MAX_PACKET);
  if(orig_at == NULL ) HIP_DEBUG("NULL orig_at sent\n"); 
  for(at_hit = orig_at; at_hit != NULL; at_hit = at_hit->next) {
    int i;
    struct sockaddr_in6 *s;
    struct in6_addr addr6;
    
    if (at_hit->family != AF_INET6)
      continue;
    
    s	= (struct sockaddr_in6 *)at_hit->addr;
    
    if (!ipv6_addr_is_hit((struct in6_addr *) at_hit->addr)) {
      continue;
    }
    
    for(at_ip = orig_at; at_ip != NULL; at_ip = at_ip->next) {

#if 0 /* LSIs not supported yet */
      if (at_ip->family == AF_INET && 
	  IS_LSI32(ntohl(((struct in_addr *) at_ip->addr)->s_addr)))
	continue;
#endif

      if (at_ip->family == AF_INET6 &&
	  ipv6_addr_is_hit((struct in6_addr *) at_ip->addr)) {
	continue;
      }
      if (at_ip->family == AF_INET) {
	IPV4_TO_IPV6_MAP(((struct in_addr *) at_ip->addr), &addr6);
      }
      else 
	addr6 = *(struct in6_addr *) at_ip->addr;

      hip_msg_init(msg);	
      HIP_DEBUG_IN6ADDR("HIT", (struct in6_addr *)at_hit->addr);
      HIP_DEBUG_IN6ADDR("IP", &addr6);
      hip_build_param_contents(msg, (void *) at_hit->addr, HIP_PARAM_HIT, sizeof(struct in6_addr));
      hip_build_param_contents(msg, (void *) &addr6, HIP_PARAM_IPV6_ADDR, sizeof(struct in6_addr));
      hip_build_user_hdr(msg, SO_HIP_ADD_PEER_MAP_HIT_IP, 0);
      hip_send_recv_daemon_info(msg);
    }
  }  
  free(msg);
}

void
get_ip_from_gaih_addrtuple(struct gaih_addrtuple *orig_at, struct in6_addr *ip)
{
  HIP_ASSERT(orig_at != NULL );
  struct gaih_addrtuple *at_ip;
  struct in6_addr addr6;

  for(at_ip = orig_at; at_ip != NULL; at_ip = at_ip->next) {
    if (at_ip->family == AF_INET && 
	IS_LSI32(ntohl(((struct in_addr *) at_ip->addr)->s_addr)))
      continue;
    if (at_ip->family == AF_INET6 &&
	ipv6_addr_is_hit((struct in6_addr *) at_ip->addr)) {
      continue;
    }
    if (at_ip->family == AF_INET) {
      IPV4_TO_IPV6_MAP(((struct in_addr *) at_ip->addr), &addr6);
      continue;
      memcpy(ip, &addr6, sizeof(struct in6_addr));
      _HIP_DEBUG_HIT("IPV4_TO_IPV6_MAP addr=", &addr6);
      _HIP_HEXDUMP("IPV4_TO_IPV6_MAP HEXDUMP ip=", ip, sizeof(struct in6_addr));
    }
    else 
      addr6 = *(struct in6_addr *) at_ip->addr;
      _HIP_DEBUG_HIT("get_ip_from_gaih_addrtuple addr=", &addr6);
      memcpy(ip, &addr6, sizeof(struct in6_addr));
      _HIP_HEXDUMP("get_ip_from_gaih_addrtuple HEXDUMP ip=", ip, sizeof(struct in6_addr));
  }  
}

int 
gaih_inet_result(struct gaih_addrtuple *at, struct gaih_servtuple *st, 
    const struct addrinfo *req, struct addrinfo **pai)
 {
   int rc;
   int v4mapped = (req->ai_family == PF_UNSPEC || req->ai_family == PF_INET6) &&
		 (req->ai_flags & AI_V4MAPPED);
   const char *c = NULL;
   struct gaih_servtuple *st2;
   struct gaih_addrtuple *at2 = at;
   size_t socklen, namelen;
   sa_family_t family;

   /*
     buffer is the size of an unformatted IPv6 address in printable format.
   */
   char buffer[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
  
   _HIP_DEBUG("Generating answer\n");
   //dump_pai(at);
   while (at2 != NULL)
     {
       if (req->ai_flags & AI_CANONNAME)
	 {
	   struct hostent *h = NULL;
	   
	   int herrno = 0;
	   struct hostent th;
	   size_t tmpbuflen = 512;
	   char *tmpbuf;

	   do
	     {
	       tmpbuflen *= 2;
	       tmpbuf = __alloca (tmpbuflen);
	       
	       if (tmpbuf == NULL)
		 return -EAI_MEMORY;

	       /* skip if at2->addr is HIT ? */
	       rc = __gethostbyaddr_r (at2->addr,
				       ((at2->family == AF_INET6)
					? sizeof(struct in6_addr)
					: sizeof(struct in_addr)),
				       at2->family, &th, tmpbuf, tmpbuflen,
				       &h, &herrno);

	     }
	   while (rc == errno && herrno == NETDB_INTERNAL);

	   if (rc != 0 && herrno == NETDB_INTERNAL)
	     {
	       __set_h_errno (herrno);
	       return -EAI_SYSTEM;
	     }
	   
	   if (h == NULL)
	     c = inet_ntop (at2->family, at2->addr, buffer, sizeof(buffer));
	   else
	     c = h->h_name;
	   
	   if (c == NULL)
	     return GAIH_OKIFUNSPEC | -EAI_NONAME;
	   
	   namelen = strlen (c) + 1;
	 }
       else
	 namelen = 0;
       
       if (at2->family == AF_INET6 || v4mapped)
	 {
	   family = AF_INET6;
	   socklen = sizeof (struct sockaddr_in6);
	  }
	else
	  {
	    family = AF_INET;
	    socklen = sizeof (struct sockaddr_in);
	  }

       for (st2 = st; st2 != NULL; st2 = st2->next)
	  {
	    *pai = malloc (sizeof (struct addrinfo) + socklen + namelen);
	    if (*pai == NULL)
	      return -EAI_MEMORY;
	    
	    (*pai)->ai_flags = req->ai_flags;
	    (*pai)->ai_family = family;
	    (*pai)->ai_socktype = st2->socktype;
	    (*pai)->ai_protocol = st2->protocol;
	    (*pai)->ai_addrlen = socklen;
	    (*pai)->ai_addr = (void *) (*pai) + sizeof(struct addrinfo);
#ifdef _HAVE_SA_LEN
	    ((struct sockaddr_un *) (*pai)->ai_addr)->sa_len =
	      socklen;
#endif /* _HAVE_SA_LEN */
	    (*pai)->ai_addr->sa_family = family;
	    
	    if (family == AF_INET6)
	      {
		struct sockaddr_in6 *sin6p =
		  (struct sockaddr_in6 *) (*pai)->ai_addr;

		sin6p->sin6_flowinfo = 0;
		if (at2->family == AF_INET6)
		  {
		    memcpy (&sin6p->sin6_addr,
			    at2->addr, sizeof (struct in6_addr));
		  }
		else
		  {
		    sin6p->sin6_addr.s6_addr32[0] = 0;
		    sin6p->sin6_addr.s6_addr32[1] = 0;
		    sin6p->sin6_addr.s6_addr32[2] = htonl(0x0000ffff);
		    memcpy(&sin6p->sin6_addr.s6_addr32[3], 
			   at2->addr, sizeof (sin6p->sin6_addr.s6_addr32[3]));
		  }
		sin6p->sin6_port = st2->port;
		sin6p->sin6_scope_id = at2->scopeid;
	      }
	    else
	      {
		struct sockaddr_in *sinp =
		  (struct sockaddr_in *) (*pai)->ai_addr;

		memcpy (&sinp->sin_addr,
			at2->addr, sizeof (struct in_addr));
		sinp->sin_port = st2->port;
		memset (sinp->sin_zero, '\0', sizeof (sinp->sin_zero));
	      }

	    if (c)
	      {
		(*pai)->ai_canonname = ((void *) (*pai) +
					sizeof (struct addrinfo) + socklen);
		strcpy ((*pai)->ai_canonname, c);
	      }
	    else
	      (*pai)->ai_canonname = NULL;

	    (*pai)->ai_next = NULL;
	    pai = &((*pai)->ai_next);
	  } /* for (st2 = st; st2 != NULL; st2 = st2->next) */
	
	at2 = at2->next;
      }
    /* changed __alloca:s for the linked list 'at' to mallocs, 
       free malloced memory from at */
    if (at) {
      free_gaih_addrtuple(at);
      /* In case the caller of tries to free at again */
      at = NULL;
    }
    if (st) {
      free_gaih_servtuple(st);
      /* In case the caller of tries to free at again */
      st = NULL;
    }
    return 0;
 }


int 
gaih_inet_get_serv(const struct addrinfo *req, const struct gaih_service *service,
		       const struct gaih_typeproto *tp, struct gaih_servtuple **st) 
{
  int rc;  

  if ((tp->protoflag & GAI_PROTO_NOSERVICE) != 0)
    return (GAIH_OKIFUNSPEC | -EAI_SERVICE);
  
  if (service->num < 0)
    {
      if (tp->name[0])
	{
	  *st = (struct gaih_servtuple *)
	    malloc (sizeof (struct gaih_servtuple));
	  
	  if ((rc = gaih_inet_serv (service->name, tp, req, *st)))
	    return rc;
	}
      else
	{
	  struct gaih_servtuple **pst = st;
	  for (tp++; tp->name[0]; tp++)
	    {
	      struct gaih_servtuple *newp;
	      
	      if ((tp->protoflag & GAI_PROTO_NOSERVICE) != 0)
		continue;
	      
	      if (req->ai_socktype != 0
		  && req->ai_socktype != tp->socktype)
		continue;
	      if (req->ai_protocol != 0
		  && !(tp->protoflag & GAI_PROTO_PROTOANY)
		  && req->ai_protocol != tp->protocol)
		continue;
	      
	      newp = (struct gaih_servtuple *)
		malloc (sizeof (struct gaih_servtuple));
	      
	      if ((rc = gaih_inet_serv (service->name, tp, req, newp)))
		{
		  if (rc & GAIH_OKIFUNSPEC)
		    continue;
		  return rc;
		}
	      
	      *pst = newp;
	      pst = &(newp->next);
	    }
	  if (*st == (struct gaih_servtuple *) &nullserv)
	    return (GAIH_OKIFUNSPEC | -EAI_SERVICE);
	}
    }
  else
    {
      *st = malloc(sizeof (struct gaih_servtuple));
      (*st)->next = NULL;
      (*st)->socktype = tp->socktype;
      (*st)->protocol = ((tp->protoflag & GAI_PROTO_PROTOANY)
			 ? req->ai_protocol : tp->protocol);
      (*st)->port = htons (service->num);
    }
  return 0;
}

int 
gaih_inet_get_name(const char *name, const struct addrinfo *req, 
		   const struct gaih_typeproto *tp, 
		   struct gaih_servtuple *st, struct gaih_addrtuple **at, 
		   int hip_transparent_mode) 
{
  int rc;
  int v4mapped = (req->ai_family == PF_UNSPEC || req->ai_family == PF_INET6) &&
    (req->ai_flags & AI_V4MAPPED);
  _HIP_DEBUG(">> name != NULL\n");
  
  *at = malloc (sizeof (struct gaih_addrtuple));
  
  (*at)->family = AF_UNSPEC;
  (*at)->scopeid = 0;
  (*at)->next = NULL;
  
  // is ipv4 address?
  if (inet_pton (AF_INET, name, (*at)->addr) > 0)
    {
      HIP_DEBUG("is IPv4\n");
      
      if (req->ai_family == AF_UNSPEC || req->ai_family == AF_INET || v4mapped)
	(*at)->family = AF_INET;
      else
	return -EAI_FAMILY;
    }
  
  // not ipv4
  if ((*at)->family == AF_UNSPEC)
    {
      char *namebuf = strdupa (name);
      char *scope_delim;
      
      _HIP_DEBUG("not IPv4\n");
      
      scope_delim = strchr (namebuf, SCOPE_DELIMITER);
      if (scope_delim != NULL)
	*scope_delim = '\0';
      
      // is ipv6 address?
      if (inet_pton (AF_INET6, namebuf, (*at)->addr) > 0)
	{
	  _HIP_DEBUG("is IPv6\n");
	  
	  if (req->ai_family == AF_UNSPEC || req->ai_family == AF_INET6)
	    (*at)->family = AF_INET6;
	  else
	    return -EAI_FAMILY;
	  
	  if (scope_delim != NULL)
	    {
	      int try_numericscope = 0;
	      if (IN6_IS_ADDR_LINKLOCAL ((*at)->addr)
		  || IN6_IS_ADDR_MC_LINKLOCAL ((*at)->addr))
		{
		  (*at)->scopeid = if_nametoindex (scope_delim + 1);
		  if ((*at)->scopeid == 0)
		    try_numericscope = 1;
		} 
	      else
		try_numericscope = 1;
	      
	      if (try_numericscope != 0)
		{
		  char *end;
		  unsigned long scopeid = strtoul (scope_delim + 1, &end,
						   10);
		  if (*end != '\0' || 
		      (sizeof((*at)->scopeid) < sizeof(scopeid) &&
		       scopeid > 0xffffffff)) 
		    return GAIH_OKIFUNSPEC | -EAI_NONAME;
		  (*at)->scopeid = (uint32_t) scopeid;
		}
	    }
	}
    }
  
  // host name is not an IP address
  if ((*at)->family == AF_UNSPEC && (req->ai_flags & AI_NUMERICHOST) == 0)
    {     
      struct gaih_addrtuple **pat = at;
      struct gaih_addrtuple *at_dns = *at;
      int no_data = 0;
      int no_inet6_data = 0;
      int old_res_options = _res.options;
      int found_hits = 0;
      
      HIP_DEBUG("not IPv4 or IPv6 address, resolve name (!AI_NUMERICHOST)\n");
      HIP_DEBUG("&pat=%p pat=%p *pat=%p **pat=%p\n", &pat, pat, *pat, **pat);
      
#ifdef UNDEF_CONFIG_HIP_AGENT
      if ((hip_transparent_mode || req->ai_flags & AI_HIP) &&
	  hip_agent_is_alive()) {
	/* Communicate the name and port output to the agent
	   synchronously with netlink. First send the name + port
	   and then wait for answer (select). The agent filters
	   or modifies the list. The agent implements gethosts_hit
	   with some filtering. */
      }
#endif
 
      /* If we are looking for both IPv4 and IPv6 address we don't
	 want the lookup functions to automatically promote IPv4
	 addresses to IPv6 addresses.  Currently this is decided
	 by setting the RES_USE_INET6 bit in _res.options.  */
      if (req->ai_family == AF_UNSPEC)
	_res.options &= ~RES_USE_INET6;
      
      if (req->ai_family == AF_UNSPEC || req->ai_family == AF_INET6 
	|| hip_transparent_mode || req->ai_flags & AI_HIP || req->ai_flags & AI_NODHT)
	 no_inet6_data = gethosts (name, AF_INET6, &pat);

      if (req->ai_family == AF_UNSPEC)
	_res.options = old_res_options;
      
      if (req->ai_family == AF_INET ||
	  (!v4mapped && req->ai_family == AF_UNSPEC) ||
	  (v4mapped && (no_inet6_data != 0 || (req->ai_flags & AI_ALL)))
  	  || hip_transparent_mode || req->ai_flags & AI_HIP & AI_NODHT)
	no_data = gethosts (name, AF_INET, &pat);

      if (hip_transparent_mode) {
	HIP_DEBUG("HIP_TRANSPARENT_API: fetch HIT addresses\n");
       
	_HIP_DEBUG("found_hits before gethosts_hit: %d\n", found_hits);
	found_hits |= gethosts_hit(name, &pat, req->ai_flags);
	_HIP_DEBUG("found_hits after gethosts_hit: %d\n", found_hits);
	
	if (req->ai_flags & AI_HIP) {
	  HIP_DEBUG("HIP_TRANSPARENT_API: AI_HIP set: do not get IPv6 addresses\n");
	} else {
	  HIP_DEBUG("HIP_TRANSPARENT_API: AI_HIP unset: get IPv6 addresses too\n");
	}
      } else /* not hip_transparent_mode */ {
	if (req->ai_flags & AI_HIP) {
	  HIP_DEBUG("no HIP_TRANSPARENT_API: AI_HIP set: get only HIT addresses\n");
	  found_hits |= gethosts_hit(name, &pat, req->ai_flags);
	} else {
	  HIP_DEBUG("no HIP_TRANSPARENT_API: AI_HIP unset: no HITs\n");
	}
      }

      _HIP_DEBUG("Dumping the structure\n");
      //dump_pai(*at);
      
      /* perform HIT-IPv6 mapping if both are found 
	 AG: now the loop also takes in IPv4 addresses */
      if (found_hits) 
	send_hipd_addr(*at);

      /*
        Check if DNS returned HITs incase hosts file and DHT checks didn't contain HITs 
      */
      if (!found_hits)
        {
          for (at_dns = *at; at_dns != NULL; at_dns = at_dns->next)
            {
              if (ipv6_addr_is_hit((struct in6_addr *)at_dns->addr)) 
                {
                  send_hipd_addr(*at);
                  break;
                }
            }
        } 

      if (no_data != 0 && no_inet6_data != 0)
	{
	  _HIP_DEBUG("nodata\n");
	  /* If both requests timed out report this.  */
	  if (no_data == EAI_AGAIN && no_inet6_data == EAI_AGAIN)
	    return -EAI_AGAIN;
	  
	  /* We made requests but they turned out no data.  The name
	     is known, though.  */
	  return (GAIH_OKIFUNSPEC | -EAI_AGAIN);
	}
      /* If there isn't any node in the list or the first node is unspecified, exit */ 
      if (*at == NULL || (*at)->family == AF_UNSPEC)
	return (GAIH_OKIFUNSPEC | -EAI_NONAME);
    
      HIP_DEBUG("req->ai_flags: %d   AI_HIP: %d  AF_UNSPEC: %d\n", req->ai_flags, AI_HIP, AF_UNSPEC);
      /* HIP: Finally remove IP addresses from the list to be
	 returned depending on the AI_HIP flag */ 
      if (req->ai_flags & AI_HIP) {
	struct gaih_addrtuple *a = *at, *p = NULL, *aux = NULL;
	HIP_DEBUG("HIP: AI_HIP set: remove IP addresses. (*at)->addr: %s (*at)->family: %d\n", (*at)->addr, (*at)->family);

	while (a != NULL) {
	  struct gaih_addrtuple *nxt = a->next;
	  
	  HIP_DEBUG("req->ai_family: %d   a->family: %d   ipv6_addr_is_hit: %d  ", 
		    req->ai_family, a->family, 
                    ipv6_addr_is_hit((struct in6_addr *)a->addr), a->addr);
	  if (a->family == AF_INET)
              hip_print_lsi("\na->addr",a->addr);
          if (a->family == AF_INET6)
              hip_print_hit("\na->addr",a->addr);

	  /* do not remove HIT if request is not IPv4 */
	  if (req->ai_family != AF_INET && 
	      a->family == AF_INET6 && 
	      ipv6_addr_is_hit((struct in6_addr *)a->addr))
	    goto leave;
	  
	  /* do not remove LSI if request is IPv4 */
	  if (req->ai_family == AF_INET && 
	      a->family == AF_INET && 
	      IS_LSI32(ntohl(((struct in_addr *)a->addr)->s_addr)))
	    goto leave;

	  if (p != NULL){
	    while (aux->next != a)
	      aux = aux->next;
	    aux->next = a->next;
	  }
	  HIP_DEBUG("freeing a\n");
	  free(a);
	  a = nxt;
	  HIP_DEBUG("pointer a: %p\tpointer p: %p\n", a, p);
	  continue;
	  
	leave:
	  if (p == NULL)
	    p = aux = a;
	  a = a->next;
	  HIP_DEBUG("pointer a: %p\tpointer p: %p\n", a, p);	
	}
	if (p == NULL){  /* no HITs or LSIs were found */
	  HIP_DEBUG(" return (GAIH_OKIFUNSPEC | -EAI_NONAME);\n");
	  return (GAIH_OKIFUNSPEC | -EAI_NONAME);
	}
	
	*at = p;
      }


      /* HIP: If AF_UNSPEC flag is set, order the link list so HITs are first and then IPs. */
      if (req->ai_flags == AF_UNSPEC) {
	struct gaih_addrtuple *a = *at, *p = NULL, *plast = NULL, *aux = *at;
	_HIP_DEBUG("HIP: AI_HIP set: order IP addresses. (*at)->addr: %s (*at)->family: %d\n", (*at)->addr, (*at)->family);  
	while (a != NULL) {
	  struct gaih_addrtuple *nxt = a->next;
	  
	  _HIP_DEBUG("req->ai_family: %d    a->family: %d    ipv6_addr_is_hit: %d a->addr: %s\n", 
		    req->ai_family, a->family, ipv6_addr_is_hit((struct in6_addr *)a->addr), a->addr);
	  
	  /* do not move HITs if request is not IPv4 */
	  if (req->ai_family != AF_INET && 
	      a->family == AF_INET6 && 
	      ipv6_addr_is_hit((struct in6_addr *)a->addr)){
	    a = aux = nxt;
	    continue;
	  }
	  
#if 0 /* Not supported yet */
	  /* do not move the LSI if request is IPv4 */
	  if (req->ai_family == AF_INET && 
	      a->family == AF_INET && 
	      IS_LSI32(ntohl(((struct in_addr *)a->addr)->s_addr))){
	    a = aux = nxt;
	    continue;
	  }
#endif

	  /* putting the IPs to the linked list *p */
	  if (p == NULL){
	    p = plast = a;
	    a->next = NULL;
	  }else{
	    plast->next = a;
	    plast = plast->next;
	    a->next = NULL;
	  }
	  if (aux == *at)
	    *at = aux = nxt;
	  else{ 
	    aux = *at;
	    while (aux->next != a)
	      aux = aux->next;
	    aux->next = nxt;
	  }

	  a = aux = nxt;
	  HIP_DEBUG("pointer a: %p\tpointer p: %p\n", a, p);
	 
	}

	/* Appending linked list *p (IPs) after HITs */
	if (p != NULL){
	  aux = *at;
	  if(aux == NULL)
	    *at = p;
	  else{
	    while (aux->next != NULL)
	      aux = aux->next;
	    aux->next = p;
	  }
	}
      }

      _HIP_DEBUG("Dumping the structure after removing IP addreses\n");
      //dump_pai(*at);
    } /* (at->family == AF_UNSPEC && (req->ai_flags & AI_NUMERICHOST) == 0) */ 
  HIP_DEBUG(" return 0;\n");
  return 0;
}

static int
gaih_inet (const char *name, const struct gaih_service *service,
	   const struct addrinfo *req, struct addrinfo **pai,
	   int hip_transparent_mode)
{
  const struct gaih_typeproto *tp = gaih_inet_typeproto;
  struct gaih_servtuple *st = (struct gaih_servtuple *) &nullserv;
  struct gaih_addrtuple *at = NULL;
  int rc;

  _HIP_DEBUG("Family %d and Flags %d\n", req->ai_family, req->ai_flags);

  if (req->ai_protocol || req->ai_socktype)
    {
      ++tp;

      while (tp->name[0]
	     && ((req->ai_socktype != 0 && req->ai_socktype != tp->socktype)
		 || (req->ai_protocol != 0
		     && !(tp->protoflag & GAI_PROTO_PROTOANY)
		     && req->ai_protocol != tp->protocol)))
	++tp;

      if (! tp->name[0])
	{
	  if (req->ai_socktype)
	    return (GAIH_OKIFUNSPEC | -EAI_SOCKTYPE);
	  else
	    return (GAIH_OKIFUNSPEC | -EAI_SERVICE);
	}
    }

  if (service != NULL) {
    rc = gaih_inet_get_serv(req, service, tp, &st);
    if (rc) 
      return rc;
  } 
  else if (req->ai_socktype || req->ai_protocol)
    {
      st = malloc (sizeof (struct gaih_servtuple));
      st->next = NULL;
      st->socktype = tp->socktype;
      st->protocol = ((tp->protoflag & GAI_PROTO_PROTOANY)
		      ? req->ai_protocol : tp->protocol);
      st->port = 0;
    }
  else
    {
      /* Neither socket type nor protocol is set.  Return all socket types
	 we know about.  */
      struct gaih_servtuple **lastp = &st;
      for (++tp; tp->name[0]; ++tp)
	{
	  struct gaih_servtuple *newp;

	  newp = malloc (sizeof (struct gaih_servtuple));
	  newp->next = NULL;
	  newp->socktype = tp->socktype;
	  newp->protocol = tp->protocol;
	  newp->port = 0;

	  *lastp = newp;
	  lastp = &newp->next;
	}
    }

  if (name != NULL) {
    rc = gaih_inet_get_name(name, req, tp, st, &at, hip_transparent_mode);
    if (rc)
      return rc;
  }
  else /* name == NULL */
    {
      struct gaih_addrtuple **pat = &at;
      struct gaih_addrtuple *atr, *attr;
      atr = at = malloc (sizeof (struct gaih_addrtuple));
      memset (at, '\0', sizeof (struct gaih_addrtuple));
      
      _HIP_DEBUG(">> name == NULL\n");
      /* Find the local HIs here and add the HITs to atr */
      if (req->ai_flags & AI_HIP) {
	_HIP_DEBUG("AI_HIP set: get only local hits.\n");     
	get_local_hits(service->name, pat);
      } 
      /* Transparent mode and !AI_HIP -> hits before ipv6 addresses? */
      if (hip_transparent_mode && !(req->ai_flags & AI_HIP)) {
	HIP_DEBUG("HIP_TRANSPARENT_MODE, AI_HIP not set:"); 
	HIP_DEBUG("get HITs before IPv6 address\n");
	get_local_hits(service->name, pat); 
	attr = at;
	while(attr->next != NULL) {
	  attr = attr->next;
	}
	attr->next = malloc(sizeof (struct gaih_addrtuple));
	memset (attr->next, '\0', sizeof (struct gaih_addrtuple));
	attr->next->family = AF_INET6;
      }

      if (req->ai_family == 0)
	{
	  at->next = malloc(sizeof (struct gaih_addrtuple));
	  memset (at->next, '\0', sizeof (struct gaih_addrtuple));
	}
      
      if (req->ai_family == 0 || req->ai_family == AF_INET6)
	{
	  at->family = AF_INET6;
	  if ((req->ai_flags & AI_PASSIVE) == 0)
	    memcpy (at->addr, &in6addr_loopback, sizeof (struct in6_addr));
	  atr = at->next;
	}

      if (req->ai_family == 0 || req->ai_family == AF_INET)
	{
	  atr->family = AF_INET;
	  if ((req->ai_flags & AI_PASSIVE) == 0)
	    *(uint32_t *) atr->addr = htonl (INADDR_LOOPBACK);
	}
    }

  if (pai == NULL) {
    _HIP_DEBUG("pai == NULL\n");
    return 0;
  }
  _HIP_DEBUG("Dumping the structure before returning results\n");
  //dump_pai(at);
  return gaih_inet_result(at, st, req, pai);  
}

static struct gaih gaih[] =
  {
    { PF_INET6, gaih_inet },
    { PF_INET, gaih_inet },
    { PF_LOCAL, gaih_local },
    { PF_UNSPEC, NULL }
  };

/**
 * getaddrinfo - retrieves the info of the specified peer
 * @param name ?
 * @param service ?
 * @param hints ?
 * @param pai ?
 *
 * Process a request for the list of known peers
 *
 * @return zero on success, or negative error value on failure
 * In case of flags set to AI_KERNEL_LIST, on success the number of elements found in the
 * database is returned
 */

int getaddrinfo (const char *name, const char *service,
	     const struct addrinfo *hints, struct addrinfo **pai)
{
  int i = 0, j = 0, last_i = 0;
  struct addrinfo *p = NULL, **end;
  struct gaih *g = gaih, *pg = NULL;
  struct gaih_service gaih_service, *pservice;
  int hip_transparent_mode;

  _HIP_DEBUG("flags=%d\n", hints->ai_flags);
  HIP_DEBUG("name='%s' service='%s'\n", name, service);
  if (hints)
    _HIP_DEBUG("ai_flags=0x%x ai_family=%d ai_socktype=%d ai_protocol=%d\n", hints->ai_flags, hints->ai_family, hints->ai_socktype, hints->ai_protocol);
  else
    _HIP_DEBUG("hints=NULL\n");

  //  if (*pai)
  // HIP_DEBUG("pai:ai_flags=%d ai_family=%d ai_socktype=%d ai_protocol=%d\n", (*pai)->ai_flags, (*pai)->ai_family, (*pai)->ai_socktype, (*pai)->ai_protocol);

  if (name != NULL && name[0] == '*' && name[1] == 0)
    name = NULL;

  if (service != NULL && service[0] == '*' && service[1] == 0)
    service = NULL;

  if (name == NULL && service == NULL)
    return EAI_NONAME;

  if (hints == NULL) {
    hints = &default_hints;
    _HIP_DEBUG("set hints=default_hints:ai_flags=0x%x ai_family=%d ai_socktype=%d ai_protocol=%d\n", hints->ai_flags, hints->ai_family, hints->ai_socktype, hints->ai_protocol);
  }

  HIP_DEBUG("flags: %x\n", hints->ai_flags);
  if (hints->ai_flags & ~(AI_PASSIVE|AI_CANONNAME|AI_NUMERICHOST|
			  AI_ADDRCONFIG|AI_V4MAPPED|AI_ALL|AI_HIP|
			  AI_HIP_NATIVE|AI_KERNEL_LIST|AI_NODHT))
    return EAI_BADFLAGS;

  if ((hints->ai_flags & AI_CANONNAME) && name == NULL)
    return EAI_BADFLAGS;

  if ((hints->ai_flags & AI_HIP) && (hints->ai_flags & AI_HIP_NATIVE))
    return EAI_BADFLAGS;

#ifdef HIP_TRANSPARENT_API
  /* Transparent mode does not work with HIP native resolver */
  hip_transparent_mode = !(hints->ai_flags & AI_HIP_NATIVE);
#else
  hip_transparent_mode = 0;
#endif
  
  if (service && service[0])
    {
      char *c;

      gaih_service.name = service;
      gaih_service.num = strtoul (gaih_service.name, &c, 10);
      if (*c)
	gaih_service.num = -1;
      else
	/* Can't specify a numerical socket unless a protocol family was
	   given. */
        if (hints->ai_socktype == 0 && hints->ai_protocol == 0)
          return EAI_SERVICE;
      pservice = &gaih_service;
    }
  else
    pservice = NULL;

  if (name == NULL && (hints->ai_flags & AI_KERNEL_LIST)) {
    socklen_t msg_len = NUM_MAX_HITS * sizeof(struct addrinfo);
    int err = 0, port, i;
    
    *pai = calloc(NUM_MAX_HITS, sizeof(struct addrinfo));
    if (*pai == NULL) {
      HIP_ERROR("Unable to allocated memory\n");
      err = -EAI_MEMORY;
      return err;
    }

    if (!pservice)
      port = 0;
    else
      port = pservice->num;
    /* This is the case which is used after BOS packet is processed, as a second parameter
     * instead of the IPPROTO_HIP we put the port number because it is needed to fill in
     * the struct sockaddr_in6 list
     */
    err = hip_recv_daemon_info(NULL, 0);
    HIP_ASSERT(0); /* XX FIXME: fix recv_daemon_msg */
    if (err < 0) {
      HIP_ERROR("getsockopt failed (%d)\n", err);
    }
    return err;
  }

  if (pai)
    end = &p;
  else
    end = NULL;

  while (g->gaih)
    {
      if (hints->ai_family == g->family || hints->ai_family == AF_UNSPEC)
	{
	  if ((hints->ai_flags & AI_ADDRCONFIG) && !addrconfig(g->family))
	    continue;
	  j++;
	  if (pg == NULL || pg->gaih != g->gaih)
	    {
	      pg = g;
	      i = g->gaih (name, pservice, hints, end, hip_transparent_mode);
	      if (i != 0)
		{
		  last_i = i;

		  if (hints->ai_family == AF_UNSPEC && (i & GAIH_OKIFUNSPEC))
		    continue;

		  if (p)
		    freeaddrinfo (p);

		  return -(i & GAIH_EAI);
		}
	      if (end)
		while(*end) end = &((*end)->ai_next);
	    }
	}
      ++g;
    }

  if (j == 0)
    return EAI_FAMILY;

  if (p) // here should be true
    {
      *pai = p;
      return 0;
    }

  if (pai == NULL && last_i == 0)
    return 0;

  if (p)
    freeaddrinfo (p);

  return last_i ? -(last_i & GAIH_EAI) : EAI_NONAME;
}

void
freeaddrinfo (struct addrinfo *ai)
{
  struct addrinfo *p;

  _HIP_DEBUG("ai=%p\n", ai);

  while (ai != NULL)
    {
      p = ai;
      ai = ai->ai_next;
      free (p);
    }
}

