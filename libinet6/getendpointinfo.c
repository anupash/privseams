/*
 * getendpointinfo: native HIP API resolver
 *
 * Authors:
 * - Miika Komu <miika@iki.fi>
 * - Anthony D. Joseph <adj@hiit.fi>
 * Copyright: Miika Komu 2004, The Inner Net License v2.00.
 * Notes:     This file uses the code in this directory from Craig Metz.
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
#include <openssl/dsa.h>
#include <net/hip.h>

#include "builder.h"
#include "tools/crypto.h"

int convert_port_string_to_number(const char *servname, in_port_t *port)
{
  int err = 0;
  struct servent *servent;
  long int strtol_port;

  servent = getservbyname(servname, NULL);
  if (servent) {
    *port = ntohs(servent->s_port);
  } else {
    /* Try strtol if getservbyname fails, e.g. if the servname is "12345". */
    strtol_port = strtol(servname, NULL, 0);
    if (strtol_port == LONG_MIN || strtol_port == LONG_MAX ||
	strtol_port <= 0) {
      HIP_PERROR("strtol failed:");
      err = EEI_NONAME;
      goto out_err;
    }
    *port = strtol_port;
  }

 out_err:

  endservent();

  return err;

}

int setmyeid(struct sockaddr_eid *my_eid,
	     const char *servname,
	     const struct endpoint *endpoint,
	     const struct if_nameindex *ifaces)
{
  int err = 0;
  struct hip_common *msg = NULL;
  int iface_num = 0;
  struct if_nameindex *iface;
  struct hip_sockaddr_eid *sa_eid;
  struct endpoint_hip *ep_hip = (struct endpoint_hip *) endpoint;
  in_port_t port;

  HIP_DEBUG("\n");

  if (ep_hip->family != PF_HIP) {
    HIP_ERROR("Only HIP endpoints are supported\n");
    err = EEI_FAMILY;
    goto out_err;
  }

  if (ep_hip->flags & HIP_ENDPOINT_FLAG_HIT) {
    HIP_ERROR("setmyeid does not support HITs yet\n");
    err = EEI_BADFLAGS;
    goto out_err;
  }

  HIP_HEXDUMP("host_id in endpoint: ", &ep_hip->id.host_id,
	      hip_get_param_total_len(&ep_hip->id.host_id));

  msg = hip_msg_alloc();
  if (!msg) {
    err = EEI_MEMORY;
    goto out_err;
  }

  if (servname == NULL || strlen(servname) == 0) {
    port = 0; /* Ephemeral port */
    goto skip_port_conversion;
  }

  err = convert_port_string_to_number(servname, &port);
  if (err) {
    HIP_ERROR("Port conversion failed (%d)\n", err);
    goto out_err;
  }

 skip_port_conversion:

  /* Handler emphemeral port number */
  if (port == 0) {
    while (port < 1024) /* XX FIXME: CHECK UPPER BOUNDARY */
	   port = rand();
  }

  HIP_DEBUG("port=%d\n", port);
  
  hip_build_user_hdr(msg, SO_HIP_SET_MY_EID, 0);
  
  err = hip_build_param_eid_endpoint(msg, ep_hip);
  if (err) {
    err = EEI_MEMORY;
    goto out_err;
  }

  for(iface = (struct if_nameindex *) ifaces;
      iface && iface->if_index != 0; iface++) {
    err = hip_build_param_eid_iface(msg, iface->if_index);
    if (err) {
      err = EEI_MEMORY;
      goto out_err;
    }
  }

  err = hip_get_global_option(msg);
  if (err) {
    err = EEI_SYSTEM;
    HIP_ERROR("Failed to send msg\n");
    goto out_err;
  }

  /* getsockopt wrote the corresponding EID into the message, use it */

  err = hip_get_msg_err(msg);
  if (err) {
    err = EEI_SYSTEM;
    goto out_err;
  }

  sa_eid = hip_get_param_contents(msg, HIP_PARAM_EID_SOCKADDR);
  if (!sa_eid) {
    err = EEI_SYSTEM;
    goto out_err;
  }

  memcpy(my_eid, sa_eid, sizeof(struct sockaddr_eid));

  /* Fill the port number also because the HIP module did not fill it */
  my_eid->eid_port = htons(port);

  HIP_DEBUG("eid val=%d, port=%d\n", htons(my_eid->eid_val),
	    htons(my_eid->eid_port));

  HIP_DEBUG("\n");
  
 out_err:

  if (msg)
    hip_msg_free(msg);

  return err;
}

int setpeereid(struct sockaddr_eid *peer_eid,
	       const char *servname,
	       const struct endpoint *endpoint,
	       const struct addrinfo *addrinfo)
{
  int err = 0;
  struct hip_common *msg = NULL;
  struct addrinfo *addr;
  struct sockaddr_eid *sa_eid;
  in_port_t port = 0;

  HIP_DEBUG("\n");

  if (endpoint->family != PF_HIP) {
    HIP_ERROR("Only HIP endpoints are supported\n");
    err = EEI_FAMILY;
    goto out_err;
  }

#ifdef CONFIG_HIP_DEBUG
  {
    struct endpoint_hip *ep_hip = (struct endpoint_hip *) endpoint;
    if (ep_hip->flags & HIP_ENDPOINT_FLAG_HIT) {
      HIP_HEXDUMP("setpeereid hit: ", &ep_hip->id.hit,
		  sizeof(struct in6_addr));
    } else {
      HIP_HEXDUMP("setpeereid hi: ", &ep_hip->id.host_id,
		  hip_get_param_total_len(&ep_hip->id.host_id));
    }
  }
#endif

  msg = hip_msg_alloc();
  if (!msg) {
    err = EEI_MEMORY;
    goto out_err;
  }

  if (servname != NULL) {
    err = convert_port_string_to_number(servname, &port);
    if (err) {
      HIP_ERROR("Port conversion failed (%d)\n", err);
      goto out_err;
    }
  }

  HIP_DEBUG("port=%d\n", port);

  hip_build_user_hdr(msg, SO_HIP_SET_PEER_EID, 0);

  err = hip_build_param_eid_endpoint(msg, (struct endpoint_hip *) endpoint);
  if (err) {
    err = EEI_MEMORY;
    goto out_err;
  }

  for(addr = (struct addrinfo *) addrinfo; addr; addr = addr->ai_next) {
    HIP_DEBUG("setpeereid addr family=%d len=%d\n",
	      addrinfo->ai_family,
	      addrinfo->ai_addrlen);
    HIP_HEXDUMP("setpeereid addr: ", addrinfo->ai_addr, addrinfo->ai_addrlen);
    err = hip_build_param_eid_sockaddr(msg, addrinfo->ai_addr,
				       addrinfo->ai_addrlen);
    if (err) {
      err = EEI_MEMORY;
      goto out_err;
    }
  }

  err = hip_get_global_option(msg);
  if (err) {
    err = EEI_SYSTEM;
    goto out_err;
  }

  /* The HIP module wrote the eid into the msg. Let's use it. */

  sa_eid = hip_get_param_contents(msg, HIP_PARAM_EID_SOCKADDR);
  if (!sa_eid) {
    err = EEI_SYSTEM;
    goto out_err;
  }
	       
  memcpy(peer_eid, sa_eid, sizeof(struct sockaddr_eid));

  /* Fill the port number also because the HIP module did not fill it */
  peer_eid->eid_port = htons(port);

 out_err:

  if (msg)
    hip_msg_free(msg);

  return err;
}

/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * XX FIXME: grep for public / private word from the filename and
 * call either load_private or load_public correspondingly.
 */
int load_hip_endpoint_pem(const char *filename,
			  struct endpoint **endpoint)
{
  int err = 0;
  DSA *dsa = NULL;

  *endpoint = NULL;

  err = load_dsa_private_key(filename, &dsa);
  if (err) {
    HIP_ERROR("Failed to load DSA public key (%d)\n", err);
    goto out_err;
  }

  // XX FIX: host_id_hdr->rdata.flags = htons(0x0200); /* key is for a host */

  err = dsa_to_hip_endpoint(dsa, endpoint, HIP_ENDPOINT_FLAG_ANON, "");
  if (err) {
    HIP_ERROR("Failed to convert DSA key to HIP endpoint (%d)\n", err);
    goto out_err;
  }

 out_err:

  if (dsa)
    DSA_free(dsa);
  if (err && *endpoint)
    free(*endpoint);

  return err;
}

void free_endpointinfo(struct endpointinfo *res)
{
  struct endpointinfo *tmp;
  
  HIP_DEBUG("\n");

  while(res) {

    if (res->ei_endpoint)
      free(res->ei_endpoint);
    
    if (res->ei_canonname)
      free(res->ei_canonname);

    HIP_DEBUG("Freeing res\n");

    /* Save the next pointer from the data structure before the data
       structure is freed. */
    tmp = res;
    res = tmp->ei_next;
    
    /* The outermost data structure must be freed last. */
    free(tmp);
  }

}

/**
 * get_localhost_endpointinfo - query endpoint info about the localhost
 * @basename: the basename for the hip/hosts file (included for easier writing
 *            of unit tests)
 * @servname: the service port name (e.g. "http" or "12345")
 * @hints:    selects which type of endpoints is going to be resolved
 * @res:      the result of the query
 *
 * This function is for libinet6 internal purposes only. This function does
 * not resolve private identities, only public identities. The locators of
 * the localhost are not resolved either because interfaces are used on the
 * localhost instead of addresses. This means that the addrlist is just zeroed
 * on the result.
 *
 * Only one identity at a time can be resolved with this function. If multiple
 * identities are needed, one needs to call this function multiple times
 * with different @basename arguments and link the results together.
 *
 * XX FIX: LOCAL RESOLVER SHOULD RESOLVE PUBLIC KEYS, NOT
 * PRIVATE. CHECK THAT IT WORKS WITH THE USER-KEY TEST PROGRAM.
 *
 * Returns: zero on success, or negative error value on failure
 */
int get_localhost_endpointinfo(const char *basename,
			       const char *servname,
			       const struct endpointinfo *hints,
			       struct endpointinfo **res)
{
  int err = 0;
  DSA *dsa = NULL;
  struct endpoint_hip *endpoint_hip = NULL;
  char hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
  struct if_nameindex *ifaces = NULL;

  *res = NULL;

  HIP_DEBUG("glhepi\n");
  HIP_ASSERT(hints);

  // XX TODO: check flags?
  memset(hostname, 0, HIP_HOST_ID_HOSTNAME_LEN_MAX);
  err = gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1);
  if (err) {
    HIP_ERROR("gethostname failed (%d)\n", err);
    err = EEI_NONAME;
    goto out_err;
  }

  /* Only private keys are handled. */
  err = load_dsa_private_key(basename, &dsa);
  if (err) {
    err = EEI_SYSTEM;
    HIP_ERROR("Loading of private key %s failed\n", basename);
    goto out_err;
  }

  err = dsa_to_hip_endpoint(dsa, &endpoint_hip, hints->ei_flags, hostname);
  if (err) {
    HIP_ERROR("Failed to allocate and build endpoint.\n");
    err = EEI_SYSTEM;
    goto out_err;
  }

  HIP_HEXDUMP("host identity in endpoint: ", &endpoint_hip->id.host_id,
	      hip_get_param_total_len(&endpoint_hip->id.host_id));


  HIP_HEXDUMP("hip endpoint: ", endpoint_hip, endpoint_hip->length);

#if 0 /* XX FIXME */
  ifaces = if_nameindex();
  if (ifaces == NULL || (ifaces->if_index == 0)) {
    HIP_ERROR("%s\n", (ifaces == NULL) ? "Iface error" : "No ifaces.");
    err = 1;
    goto out_err;
  }
#endif

  *res = calloc(1, sizeof(struct endpointinfo));
  if (!*res) {
    err = EEI_MEMORY;
    goto out_err;
  }

  (*res)->ei_endpoint = malloc(sizeof(struct sockaddr_eid));
  if (!(*res)->ei_endpoint) {
    err = EEI_MEMORY;
    goto out_err;
  }

  if (hints->ei_flags & EI_CANONNAME) {
    int len = strlen(hostname) + 1;
    if (len > 1) {
      (*res)->ei_canonname = malloc(len);
      if (!((*res)->ei_canonname)) {
	err = EEI_MEMORY;
	goto out_err;
      }
      memcpy((*res)->ei_canonname, hostname, len);
    }
  }

  err = setmyeid(((struct sockaddr_eid *) (*res)->ei_endpoint), servname,
		 (struct endpoint *) endpoint_hip, ifaces);
  if (err) {
    HIP_ERROR("Failed to set up my EID (%d)\n", err);
    err = EEI_SYSTEM;
    goto out_err;
  }
  
#if CONFIG_HIP_DEBUG
  {
    struct sockaddr_eid *eid = (struct sockaddr_eid *) (*res)->ei_endpoint;
    HIP_DEBUG("eid family=%d value=%d\n", eid->eid_family,
	      ntohs(eid->eid_val));
  }
#endif

  (*res)->ei_flags = 0; /* FIXME: what about anonymous identities? */
  (*res)->ei_family = PF_HIP;
  (*res)->ei_socktype = hints->ei_socktype;
  (*res)->ei_protocol = hints->ei_protocol;
  (*res)->ei_endpointlen = sizeof(struct sockaddr_eid);
  /* ei_endpoint has already been set */
  /* canonname has already been set */
  (*res)->ei_next = NULL; /* only one local HI currently supported */

 out_err:

  if (dsa)
    DSA_free(dsa);

  if (endpoint_hip)
    free(endpoint_hip);

  if (ifaces)
    if_freenameindex(ifaces);

  /* Free allocated memory on error. Nullify the result in case the
     caller tries to deallocate the result twice with free_endpointinfo. */
  if (err) {
    if (*res) {
      if ((*res)->ei_endpoint)
	free((*res)->ei_endpoint);
      if ((*res)->ei_canonname)
	free((*res)->ei_canonname);

      free(*res);
      *res = NULL;
    }
  }

  return err;
}

static char* hip_in6_ntop(const struct in6_addr *in6, char *buf)
{
        if (!buf)
                return NULL;
        sprintf(buf,
                "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
                ntohs(in6->s6_addr16[0]), ntohs(in6->s6_addr16[1]),
                ntohs(in6->s6_addr16[2]), ntohs(in6->s6_addr16[3]),
                ntohs(in6->s6_addr16[4]), ntohs(in6->s6_addr16[5]),
                ntohs(in6->s6_addr16[6]), ntohs(in6->s6_addr16[7]));
        return buf;
}

/**
 * get_kernel_peer_list - query kernel for list of known peers
 * @nodename:  the name of the peer to be resolved
 * @servname:  the service port name (e.g. "http" or "12345")
 * @hints:    selects which type of endpoints is going to be resolved
 * @res:       the result of the query
 * @alt_flag:  flag for an alternate query (after a file query has been done)
 *             This flag will add entries (if found) to an existing result
 *
 * This function is for libinet6 internal purposes only.
 *
 * Returns: zero on success, or negative error value on failure
 *
 */
int get_kernel_peer_list(const char *nodename, const char *servname,
			 const struct endpointinfo *hints, 
			 struct endpointinfo **res, int alt_flag)
{
  int err = 0;
  struct hip_common *msg = NULL;
  unsigned int *count, *acount;
  struct hip_host_id *host_id;
  hip_hit_t *hit;
  struct in6_addr *addr;
  int i, j;
  struct endpointinfo *einfo = NULL;
  char *fqdn_str;
  int nodename_str_len = 0;
  int fqdn_str_len = 0;
  struct endpointinfo *previous_einfo = NULL;
  /* Only HITs are supported, so endpoint_hip is statically allocated */
  struct endpoint_hip endpoint_hip;
  in_port_t port = 0;
  struct addrinfo ai_hints, *ai_tail, *ai_res = NULL;
  char hit_str[46];

  if (!alt_flag)
    *res = NULL; /* The NULL value is used in the loop below. */
  
  HIP_DEBUG("\n");
  HIP_ASSERT(hints);

  if (nodename != NULL)
    nodename_str_len = strlen(nodename);

  memset(&ai_hints, 0, sizeof(struct addrinfo));
  /* ai_hints.ai_flags = hints->ei_flags; */
  /* Family should be AF_ANY but currently the HIP module supports only IPv6.
     In any case, the family cannot be copied directly from hints, because
     it contains PF_HIP. */
  ai_hints.ai_family = AF_INET6;
  ai_hints.ai_socktype = hints->ei_socktype;
  ai_hints.ai_protocol = hints->ei_protocol;

  /* The getaddrinfo is called only once and the results are copied in each
     element of the endpointinfo linked lists. */
  err = getaddrinfo(NULL, servname, &ai_hints, &ai_res);
  if (err) {
    HIP_ERROR("getaddrinfo failed: %s", gai_strerror(err));
    goto out_err;
  }

  /* Call the kernel to get the list of known peer addresses */
  msg = hip_msg_alloc();
  if (!msg) {
    err = EEI_MEMORY;
    goto out_err;
  }

  /* Build the message header */
  err = hip_build_user_hdr(msg, SO_HIP_GET_PEER_LIST, 0);
  if (err) {
    err = EEI_MEMORY;
    goto out_err;
  }
  
  /* Call the kernel */
  err = hip_get_global_option(msg);
  if (err) {
    err = EEI_SYSTEM;
    HIP_ERROR("Failed to send msg\n");
    goto out_err;
  }

  /* getsockopt wrote the peer list into the message, now process it
   * Format is:
     <unsigned integer> - Number of entries
     [<host id> - Host identifier
      <hit> - HIT
      <unsigned integer> - Number of addresses
      [<ipv6 address> - IPv6 address
       ...]
     ...]
  */
  err = hip_get_msg_err(msg);
  if (err) {
    err = EEI_SYSTEM;
    goto out_err;
  }

  /* Get count of entries in peer list */
  count = hip_get_param_contents(msg, HIP_PARAM_UINT);
  if (!count) {
    err = EEI_SYSTEM;
    goto out_err;
  }

  for (i = 0; i < *count; i++) {
    /* Get the next peer HOST ID */
    host_id = hip_get_param(msg, HIP_PARAM_HOST_ID);
    if (!host_id) {
      HIP_ERROR("no host identity pubkey in response\n");
      err = EEI_SYSTEM;
      goto out_err;
    }

    /* Extract the peer hostname, and determine its length */
    fqdn_str = hip_get_param_host_id_hostname(host_id);
    fqdn_str_len = strlen(fqdn_str);

    /* Get the peer HIT */
    hit = (hip_hit_t *) hip_get_param_contents(msg, HIP_PARAM_HIT);
    if (!hit) {
      HIP_ERROR("no hit in response\n");
      err = EEI_SYSTEM;
      goto out_err;
    }

    /* Get the number of addresses */
    acount = hip_get_param_contents(msg, HIP_PARAM_UINT);
    if (!acount) {
      err = EEI_SYSTEM;
      goto out_err;
    }

    /* Parse the hit into text form for comparison below */
    hip_in6_ntop((const struct in6_addr *)&hit, hit_str);

    /* Check if the nodename or the endpoint in the hints matches the
       scanned entries. */
    if (nodename_str_len && (fqdn_str_len == nodename_str_len) &&
	(strcmp(fqdn_str, nodename) == 0)) {
      /* XX FIX: foobar should match to foobar.org, depending on resolv.conf */
      HIP_DEBUG("Nodename match\n");
    } else if(hints->ei_endpointlen && hints->ei_endpoint &&
	      (strlen(hit_str) == hints->ei_endpointlen) &&
	      (strcmp(hit_str, (char *) hints->ei_endpoint) == 0)) {
      HIP_DEBUG("Endpoint match\n");
    } else if (!nodename_str_len) {
      HIP_DEBUG("Null nodename, returning as matched\n");
    } else {
      /* Not matched, so skip the addresses in the kernel response */
      for (j = 0; j < *acount; j++) {
	addr = (struct in6_addr *)hip_get_param_contents(msg,
							 HIP_PARAM_IPV6_ADDR);
	if (!addr) {
	  HIP_ERROR("no ip addr in response\n");
	  err = EEI_SYSTEM;
	  goto out_err;
	}
      }
      continue;
    }
      
    /* Allocate a new endpointinfo */
    einfo = calloc(1, sizeof(struct endpointinfo));
    if (!einfo) {
      err = EEI_MEMORY;
      goto out_err;
    }

    /* Allocate a new endpoint */
    einfo->ei_endpoint = calloc(1, sizeof(struct sockaddr_eid));
    if (!einfo->ei_endpoint) {
      err = EEI_MEMORY;
      goto out_err;
    }
    
    /* Copy the name if the flag is set */
    if (hints->ei_flags & EI_CANONNAME) {
      einfo->ei_canonname = malloc(fqdn_str_len + 1);
      if (!(einfo->ei_canonname)) {
	err = EEI_MEMORY;
	goto out_err;
      }
      HIP_ASSERT(strlen(fqdn_str) == fqdn_str_len);
      strcpy(einfo->ei_canonname, fqdn_str);
      /* XX FIX: we should append the domain name if it does not exist */
    }

    _HIP_DEBUG("*** %p %p\n", einfo, previous_einfo);
    
    HIP_ASSERT(einfo); /* Assertion 1 */
    
    /* Allocate and fill the HI. Note that here we are assuming that the
       endpoint is really a HIT. The following assertion checks that we are
       dealing with a HIT. Change the memory allocations and other code when
       HIs are really supported. */
    
    memset(&endpoint_hip, 0, sizeof(struct endpoint_hip));
    endpoint_hip.family = PF_HIP;

    /* Only HITs are supported, so endpoint_hip is not dynamically allocated
       and sizeof(endpoint_hip) is enough */
    endpoint_hip.length = sizeof(struct endpoint_hip);
    endpoint_hip.flags = HIP_ENDPOINT_FLAG_HIT;
    memcpy(&endpoint_hip.id.hit, hit, sizeof(struct in6_addr));
    
    HIP_HEXDUMP("peer HIT: ", &endpoint_hip.id.hit, sizeof(struct in6_addr));
    
    HIP_ASSERT(einfo && einfo->ei_endpoint); /* Assertion 2 */

    /* Now replace the addresses that we got from getaddrinfo in the ai_res
       structure, with the entries from the kernel. If there are not enough
       entries already present, allocate and fill new ones */
    ai_tail = ai_res;
    for (j = 0; j < *acount; j++, ai_tail = ai_tail->ai_next) {
      addr = (struct in6_addr *) hip_get_param_contents(msg,
							HIP_PARAM_IPV6_ADDR);
      if (!addr) {
	HIP_ERROR("no ip addr in response\n");
	err = EEI_SYSTEM;
	goto out_err;
      }

      /* Should we always include our entries, even if there are none? */
      if (!ai_res) continue;

      if (!ai_tail) { 
	/* We ran out of entries, so copy the first one so we get the
	   flags and other info*/
	ai_tail = malloc(sizeof(struct addrinfo));
	memcpy(ai_tail, ai_res, sizeof(struct addrinfo));
	ai_tail->ai_addr = malloc(sizeof(struct sockaddr_in6));
	memcpy(ai_tail->ai_addr, ai_res->ai_addr,sizeof(struct sockaddr_in6));
	ai_tail->ai_canonname = malloc(strlen(ai_res->ai_canonname)+1);
	strcpy(ai_tail->ai_canonname, ai_res->ai_canonname);
      }

      /* Now, save the address from the kernel */
      memcpy(&(((struct sockaddr_in6 *)ai_tail->ai_addr)->sin6_addr), addr, 
	       sizeof(struct in6_addr));
    }

    /* Call the kernel for the peer eid */
    err = setpeereid((struct sockaddr_eid *) einfo->ei_endpoint, servname,
		     (struct endpoint *) &endpoint_hip, ai_res);
    if (err) {
      HIP_ERROR("association failed (%d): %s\n", err);
      goto out_err;
    }
    
    /* Fill the rest of the fields in the einfo */
    einfo->ei_flags = hints->ei_flags;
    einfo->ei_family = PF_HIP;
    einfo->ei_socktype = hints->ei_socktype;
    einfo->ei_protocol = hints->ei_protocol;
    einfo->ei_endpointlen = sizeof(struct sockaddr_eid);
    
    /* The einfo structure has been filled now. Now, append it to the linked
       list. */
    
    /* Set res point to the first memory allocation, so that the starting
       point of the linked list will not be forgotten. The res will be set
       only once because on the next iteration of the loop it will non-null. */
    if (!*res)
      *res = einfo;
    
    HIP_ASSERT(einfo && einfo->ei_endpoint && *res); /* 3 */
    
    /* Link the previous endpoint info structure to this new one. */
    if (previous_einfo) {
      previous_einfo->ei_next = einfo;
    }
    
    /* Store a pointer to this einfo so that we can link this einfo to the
       following einfo on the next iteration. */
    previous_einfo = einfo;
    
    HIP_ASSERT(einfo && einfo->ei_endpoint && *res &&
	       previous_einfo == einfo); /* 4 */
  }
  
  HIP_DEBUG("Kernel list scanning ended\n");
  
 out_err:
  
  if (ai_res)
    freeaddrinfo(ai_res);
  
  if (msg)
    hip_msg_free(msg);

  /* Free all of the reserved memory on error */
  if (err) {
    /* Assertions 1, 2 and 3: einfo has not been linked to *res and
       it has to be freed separately. In English: free only einfo
       if it has not been linked into the *res list */
    if (einfo && previous_einfo != einfo) {
      if (einfo->ei_endpoint)
	free(einfo->ei_endpoint);
      if (einfo->ei_canonname)
	free(einfo->ei_canonname);
      free(einfo);
    }
    
    /* Assertion 4: einfo has been linked into the *res. Free all of the
     *res list elements (einfo does not need be freed separately). */
    if (*res) {
      free_endpointinfo(*res);
      /* In case the caller of tries to free the res again */
      *res = NULL;
    }
  }
  
  return err;
}

/**
 * get_peer_endpointinfo - query endpoint info about a peer
 * @hostsfile: the filename where the endpoint information is stored
 * @nodename:  the name of the peer to be resolved
 * @servname:  the service port name (e.g. "http" or "12345")
 * @hints:     selects which type of endpoints is going to be resolved
 * @res:       the result of the query
 *
 * This function is for libinet6 internal purposes only.
 *
 * Returns: zero on success, or negative error value on failure
 *
 */
int get_peer_endpointinfo(const char *hostsfile,
			  const char *nodename,
			  const char *servname,
			  const struct endpointinfo *hints,
			  struct endpointinfo **res)
{
  int err = 0;
  unsigned int lineno = 0;
  FILE *hosts = NULL;
  char hi_str[GEPI_HI_STR_VAL_MAX+1], fqdn_str[GEPI_FQDN_STR_VAL_MAX+1];
  struct endpointinfo *einfo = NULL;
  struct addrinfo ai_hints, *ai_res = NULL;
  struct endpointinfo *previous_einfo = NULL;
  /* Only HITs are supported, so endpoint_hip is statically allocated */
  struct endpoint_hip endpoint_hip;

  *res = NULL; /* The NULL value is used in the loop below. */

  HIP_DEBUG("\n");

  HIP_ASSERT(nodename);
  HIP_ASSERT(hints);

  hosts = fopen(hostsfile, "r");
  if (!hosts) {
    err = EEI_SYSTEM;
    HIP_ERROR("Failed to open %s\n", _PATH_HIP_HOSTS);
    goto out_err;
  }

  memset(&ai_hints, 0, sizeof(struct addrinfo));
  ai_hints.ai_flags = hints->ei_flags;
  /* Family should be AF_ANY but currently the HIP module supports only IPv6.
     In any case, the family cannot be copied directly from hints, because
     it contains PF_HIP. */
  ai_hints.ai_family = AF_INET6;
  ai_hints.ai_socktype = hints->ei_socktype;
  ai_hints.ai_protocol = hints->ei_protocol;

  /* The getaddrinfo is called only once and the results are copied in each
     element of the endpointinfo linked lists. */
  err = getaddrinfo(nodename, servname, &ai_hints, &ai_res);
  if (err) {
    HIP_ERROR("getaddrinfo failed: %s", gai_strerror(err));
    /* goto out_err; */
    goto fallback;
  }

  /* XX TODO: check and handle flags here */

  HIP_ASSERT(!*res); /* Pre-loop invariable */

  /* XX TODO: reverse the order of hi_str and fqdn_str in the
     /etc/hosts file? */

  while(fscanf(hosts, "%" GEPI_HI_STR_MAX "s %" GEPI_FQDN_STR_MAX "s",
	       hi_str, fqdn_str) == 2) {
    unsigned int hi_str_len = strlen(hi_str); /* trailing \0 is excluded */
    unsigned int fqdn_str_len = strlen(fqdn_str); /* the same here */

    lineno++;

    /* Check if the nodename or the endpoint in the hints matches to the
       scanned entries. */
    if (fqdn_str_len == strlen(nodename) &&
	strcmp(fqdn_str, nodename) == 0) {
      /* XX FIX: foobar should match to foobar.org, depending on resolv.conf */
      HIP_DEBUG("Nodename match on line %d\n", lineno);
    } else if(hints->ei_endpointlen && hints->ei_endpoint &&
	      hi_str_len == hints->ei_endpointlen &&
	      (strcmp(hi_str, (char *) hints->ei_endpoint) == 0)) {
      HIP_DEBUG("Endpoint match on line %d\n", lineno);
    } else {
      HIP_DEBUG("No match on line %d, skipping\n", lineno);
      continue;
    }
    
    einfo = calloc(1, sizeof(struct endpointinfo));
    if (!einfo) {
      err = EEI_MEMORY;
      goto out_err;
    }

    einfo->ei_endpoint = calloc(1, sizeof(struct sockaddr_eid));
    if (!einfo->ei_endpoint) {
      err = EEI_MEMORY;
      goto out_err;
    }
    
    if (hints->ei_flags & EI_CANONNAME) {
      einfo->ei_canonname = malloc(fqdn_str_len + 1);
      if (!(einfo->ei_canonname)) {
	err = EEI_MEMORY;
	goto out_err;
      }
      HIP_ASSERT(strlen(fqdn_str) == fqdn_str_len);
      strcpy(einfo->ei_canonname, fqdn_str);
      /* XX FIX: we should append the domain name if it does not exist */
    }

    _HIP_DEBUG("*** %p %p\n", einfo, previous_einfo);
    
    HIP_ASSERT(einfo); /* Assertion 1 */
    
    /* Allocate and fill the HI. Note that here we are assuming that the
       endpoint is really a HIT. The following assertion checks that we are
       dealing with a HIT. Change the memory allocations and other code when
       HIs are really supported. */
    HIP_ASSERT(hi_str_len == 4 * 8 + 7 * 1);
    
    memset(&endpoint_hip, 0, sizeof(struct endpoint_hip));
    endpoint_hip.family = PF_HIP;

    /* Only HITs are supported, so endpoint_hip is not dynamically allocated
       and sizeof(endpoint_hip) is enough */
    endpoint_hip.length = sizeof(struct endpoint_hip);
    endpoint_hip.flags = HIP_ENDPOINT_FLAG_HIT;
    
    if (inet_pton(AF_INET6, hi_str, &endpoint_hip.id.hit) <= 0) {
      HIP_ERROR("Failed to convert string %s to HIT\n", hi_str);
      err = EEI_FAIL;
      goto out_err;
    }
    
    HIP_DEBUG("hi str: %s\n", hi_str);
    HIP_HEXDUMP("peer HIT: ", &endpoint_hip.id.hit, sizeof(struct in6_addr));
    
    HIP_ASSERT(einfo && einfo->ei_endpoint); /* Assertion 2 */
    
    err = setpeereid((struct sockaddr_eid *) einfo->ei_endpoint, servname,
		     (struct endpoint *) &endpoint_hip, ai_res);
    if (err) {
      HIP_ERROR("association failed (%d): %s\n", err);
      goto out_err;
    }
    
    /* Fill the rest of the fields in the einfo */
    einfo->ei_flags = hints->ei_flags;
    einfo->ei_family = PF_HIP;
    einfo->ei_socktype = hints->ei_socktype;
    einfo->ei_protocol = hints->ei_protocol;
    einfo->ei_endpointlen = sizeof(struct sockaddr_eid);
    
    /* The einfo structure has been filled now. Now, append it to the linked
       list. */
    
    /* Set res point to the first memory allocation, so that the starting
       point of the linked list will not be forgotten. The res will be set
       only once because on the next iteration of the loop it will non-null. */
    if (!*res)
      *res = einfo;
    
    HIP_ASSERT(einfo && einfo->ei_endpoint && *res); /* 3 */
    
    /* Link the previous endpoint info structure to this new one. */
    if (previous_einfo) {
      previous_einfo->ei_next = einfo;
    }
    
    /* Store a pointer to this einfo so that we can link this einfo to the
       following einfo on the next iteration. */
    previous_einfo = einfo;
    
    HIP_ASSERT(einfo && einfo->ei_endpoint && *res &&
	       previous_einfo == einfo); /* 4 */
  }
  
  HIP_DEBUG("Scanning ended\n");

 fallback:
  /* If no entries are found, fallback on the kernel's list */
  if (!*res) {
    HIP_DEBUG("No entries found, calling kernel for entries\n");
    err = get_kernel_peer_list(nodename, servname, hints, res, 1);
    HIP_DEBUG("Done with kernel entries\n");
  }
  
 out_err:
  
  if (ai_res)
    freeaddrinfo(ai_res);
  
  if (hosts)
    err = fclose(hosts);

  /* Free all of the reserved memory on error */
  if (err) {
    /* Assertions 1, 2 and 3: einfo has not been linked to *res and
       it has to be freed separately. In English: free only einfo
       if it has not been linked into the *res list */
    if (einfo && previous_einfo != einfo) {
      if (einfo->ei_endpoint)
	free(einfo->ei_endpoint);
      if (einfo->ei_canonname)
	free(einfo->ei_canonname);
      free(einfo);
    }
    
    /* Assertion 4: einfo has been linked into the *res. Free all of the
     *res list elements (einfo does not need be freed separately). */
    if (*res) {
      free_endpointinfo(*res);
      /* In case the caller of tries to free the res again */
      *res = NULL;
    }
  }
  
  return err;
}

int getendpointinfo(const char *nodename, const char *servname,
		    const struct endpointinfo *hints,
		    struct endpointinfo **res)
{
  int err = 0;
  struct endpointinfo modified_hints;

  HIP_DEBUG("\n");

  /* Only HIP is currently supported */
  if (hints && hints->ei_family != PF_HIP) {
    err = -EEI_FAMILY;
    HIP_ERROR("Only HIP is currently supported\n");
    goto err_out;
  }

  if (hints) {
    memcpy(&modified_hints, hints, sizeof(struct endpointinfo));
  } else {
    /* No hints given, assign default hints */
    memset(&modified_hints, 0, sizeof(struct endpointinfo));
    modified_hints.ei_family = PF_HIP;
  }
  /* getaddrinfo has been modified to support the legacy HIP API and this
     ensures that the legacy API does not do anything funny */
  modified_hints.ei_flags |= AI_HIP_NATIVE;

  /* Note about the hints: the hints is overloaded with AI_XX and EI_XX flags.
     We make the (concious and lazy) decision not to separate them into
     different flags and assume that both getendpointinfo and getaddrinfo
     can survive the overloaded flags. The AI_XX and EI_XX in netdb.h have
     distinct values, so this should be ok. */

  /* Check for kernel list request */
  if (modified_hints.ei_flags & AI_KERNEL_LIST) {
    err = get_kernel_peer_list(nodename, servname, &modified_hints, res, 0);
    goto err_out;
  }

  if (nodename == NULL) {
    char *basename = DEFAULT_CONFIG_DIR "/" DEFAULT_HOST_DSA_KEY_FILE_BASE;
    err = get_localhost_endpointinfo(basename, servname, &modified_hints, res);
  } else {
    err = get_peer_endpointinfo(_PATH_HIP_HOSTS, nodename, servname,
				&modified_hints, res);
  }
  
 err_out:

  return err;
}

const char *gepi_strerror(int errcode)
{
  HIP_DEBUG("\n");
  return __FUNCTION__ " not implemented yet";
}
