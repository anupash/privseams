/*
 * getendpointinfo: native HIP API resolver
 *
 * Author:    Miika Komu <miika@iki.fi>
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
  if (!servent) {
    /* Try strtol if getservbyname fails, e.g. if the servname is "12345". */
    strtol_port = strtol(servname, NULL, 0);
    if (strtol_port == LONG_MIN || strtol_port == LONG_MAX ||
	strtol_port <= 0) {
      HIP_PERROR("strtol failed:");
      err = EEI_NONAME;
      goto out_err;
    } else if (port <= 0) {
      HIP_ERROR("Invalid port: %d\n", port);
      err = EEI_NONAME;
      goto out_err;
    }
    *port = strtol_port;
  } else {
    *port = ntohs(servent->s_port);
  }

 out_err:
  return err;

}

int setmyeid(int sockfd, struct sockaddr_eid *my_eid,
	     const char *servname,
	     struct endpoint *endpoint,
	     struct if_nameindex *ifaces)
{
  int err = 0;
  struct hip_common *msg = NULL;
  int iface_num = 0;
  struct if_nameindex *iface;
  struct hip_sockaddr_eid *sa_eid;
  struct endpoint_hip *ep_hip = (struct endpoint_hip *) endpoint;
  in_port_t port;
  int len;

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

  HIP_HEXDUMP("host_id in endpoint: ", &ep_hip->id.host_id, hip_get_param_total_len(&ep_hip->id.host_id));

  msg = hip_msg_alloc();
  if (!msg) {
    err = EEI_MEMORY;
    goto out_err;
  }

  if (strlen(servname) == 0) {
    port = 0;
    goto skip_port_conversion;
  }

  err = convert_port_string_to_number(servname, &port);
  if (err) {
    HIP_ERROR("Port conversion failed (%d)\n", err);
    goto out_err;
  }

 skip_port_conversion:

  /* Handler "don't care" port number */
  if (port == 0) {
    while (port < 1024) // XX FIXME: CHECK UPPER BOUNDARY
	   port = rand();
  }

  HIP_DEBUG("port=%d\n", port);
  
  hip_build_user_hdr(msg, HIP_USER_SET_MY_EID, 0);
  
  err = hip_build_param_eid_endpoint(msg, ep_hip);
  if (err) {
    err = EEI_MEMORY;
    goto out_err;
  }

  for(iface = ifaces; iface && iface->if_index != 0; iface++) {
    err = hip_build_param_eid_iface(msg, iface->if_index);
    if (err) {
      err = EEI_MEMORY;
      goto out_err;
    }
  }

  len = hip_get_msg_total_len(msg);
  err = getsockopt(sockfd, IPPROTO_HIP, SO_HIP_SET_MY_EID, msg, &len);
  if (err) {
    HIP_ERROR("getsockopt for my eid failed (%d)\n", err);
    err = EEI_SYSTEM;
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

  HIP_DEBUG("eid port=%d\n", htons(my_eid->eid_port));

  HIP_DEBUG("\n");
  
 out_err:

  if (msg)
    hip_msg_free(msg);

  return err;
}

int setpeereid(struct sockaddr_eid *peer_eid,
	       const char *servname,
	       struct endpoint *endpoint,
	       struct addrinfo *addrinfo)
{
  int err = 0;
  struct hip_common *msg = NULL;
  struct addrinfo *addr;
  struct sockaddr_eid *sa_eid;
  in_port_t port;

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

  err = convert_port_string_to_number(servname, &port);
  if (err) {
    HIP_ERROR("Port conversion failed (%d)\n", err);
    goto out_err;
  }

  HIP_DEBUG("port=%d\n", port);

  hip_build_user_hdr(msg, HIP_USER_SET_PEER_EID, 0);

  err = hip_build_param_eid_endpoint(msg, (struct endpoint_hip *) endpoint);
  if (err) {
    err = EEI_MEMORY;
    goto out_err;
  }

  for(addr = addrinfo; addr; addr = addr->ai_next) {
    HIP_DEBUG("setpeereid addr family=%d len=%d\n",
	      addrinfo->ai_family,
	      addrinfo->ai_addrlen);
    _HIP_HEXDUMP("setpeereid addr: ", addrinfo->ai_addr, addrinfo->ai_addrlen);
    err = hip_build_param_eid_sockaddr(msg, addrinfo->ai_addr,
				       addrinfo->ai_addrlen);
    if (err) {
      err = EEI_MEMORY;
      goto out_err;
    }
  }

  err = send_msg(msg);
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

int load_hip_endpoint_pem(char *filebasename, struct endpoint **endpoint)
{
  int err = 0;
  DSA *dsa = NULL;

  *endpoint = NULL;

  err = load_dsa_private_key(filebasename, &dsa);
  if (err) {
    HIP_ERROR("Failed to load DSA private key (%d)\n", err);
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

  /* Deallocate dynamically allocated addresses. The first static one (the
     clone) is skipped. Note that actual first element was already freed in
     getendpointinfo. The addresses are freed only once here (and not in the
     loop) because they were allocated only once in the getendpointinfo: each
     endpointinfo contains just a pointer to the list. */
  if (res && res->ei_addrlist.ai_next)
    freeaddrinfo(res->ei_addrlist.ai_next);
       
  while(res) {

    if (res->ei_endpoint)
      free(res->ei_endpoint);

    /* Save the next pointer from the data structure before the data
       structure is freed. */
    tmp = res;
    res = tmp->ei_next;
    
    /* The outermost data structure must be freed last. */
    free(tmp);
  }

 out:
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
 * Returns: zero on success, or negative error value on failure
 *
 * XX TODO: MAN queue
 */
int get_localhost_endpointinfo(const char *basename,
			       const char *servname,
			       const struct endpointinfo *hints,
			       struct endpointinfo **res)
{
  int err = 0;
  DSA *dsa = NULL;
  struct endpoint_hip *endpoint = NULL;
  char hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];

  *res = NULL;

  HIP_DEBUG("\n");

  // XX TODO: check flags?

  memset(hostname, 0, HIP_HOST_ID_HOSTNAME_LEN_MAX);
  err = gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1);
  if (err) {
    HIP_ERROR("gethostname failed (%d)\n", err);
    err = EEI_NONAME;
    goto out_err;
  }

  /* The resolver handles only public keys. There is another interface for
     parsing and sending private keys to the HIP module. */
  err = load_dsa_public_key(basename, &dsa);
  if (err) {
    err = EEI_SYSTEM;
    HIP_ERROR("Loading of public key %s failed\n", basename);
    goto out_err;
  }

  err = dsa_to_hip_endpoint(dsa, &endpoint, hints->ei_flags, hostname);
  if (err) {
    HIP_ERROR("Failed to allocate and build endpoint.\n");
    err = EEI_SYSTEM;
    goto out_err;
  }

  HIP_HEXDUMP("host identity in endpoint: ", &endpoint->id.host_id,
	      hip_get_param_total_len(&endpoint->id.host_id));


  HIP_HEXDUMP("endpoint: ", endpoint, endpoint->length);

  *res = malloc(sizeof(struct endpointinfo));
  if (!*res) {
    err = EEI_MEMORY;
    goto out_err;
  }
  memset(*res, 0, sizeof(struct endpointinfo));

  (*res)->ei_family = hints->ei_family;
  (*res)->ei_endpoint = (struct endpoint *) endpoint;
  (*res)->ei_flags = 0; /* FIXME: what about anonymous identities? */

 out_err:

  if (dsa)
    DSA_free(dsa);

  /* Free allocated memory on error. Nullify the result in case the
     caller tries to deallocate the result twice with free_endpointinfo. */
  if (err) {
    if (*res) {
      if ((*res)->ei_endpoint) {
	free((*res)->ei_endpoint);
      }
      free(*res);
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
 * XX TODO: MAN QUEUE
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
  struct addrinfo *ai_res = NULL;
  struct endpointinfo *previous_einfo = NULL;
  struct endpoint_hip *endpoint_hip;

  *res = NULL; /* The NULL value is used in the loop below. */

  HIP_DEBUG("\n");

  HIP_ASSERT(nodename);

  hosts = fopen(hostsfile, "r");
  if (!hosts) {
    err = EEI_SYSTEM;
    HIP_ERROR("Failed to open %s\n", _PATH_HIP_HOSTS);
    goto out_err;
  }

  /* The getaddrinfo is called only once and the results are copied in each
     element of the endpointinfo linked lists. */
  err = getaddrinfo(nodename, servname, &hints->ei_addrlist, &ai_res);
  if (err) {
    HIP_ERROR("getaddrinfo failed: %s", gai_strerror(err));
    goto out_err;
  }

  /* XX TODO: handle flags */

  HIP_ASSERT(!*res); /* Pre-loop invariable */

  /* XX TODO: reverse hi_str and fqdn_str */
  while(fscanf(hosts, "%" GEPI_HI_STR_MAX "s %" GEPI_FQDN_STR_MAX "s",
	       hi_str, fqdn_str) == 2) {
    unsigned int hi_str_len = strlen(hi_str); /* trailing \0 is excluded */

    lineno++;

    /* Check if the nodename or the endpoint in the hints matches to the
       scanned entries. */
    if (strlen(fqdn_str) == strlen(nodename) &&
	strcmp(fqdn_str, nodename) == 0) {
      /* XX FIX: foobar should match to foobar.org, depending on resolv.conf */
      HIP_DEBUG("Nodename match on line %d\n", lineno);
    } else if(hints->ei_endpoint &&
	      hi_str_len == strlen((char *) hints->ei_endpoint) &&
	      strcmp(hi_str, (char *) hints->ei_endpoint) == 0) {
      HIP_DEBUG("Endpoint match on line %d\n", lineno);
    } else {
      HIP_DEBUG("No match on line %d, skipping\n", lineno);
      continue;
    }

    einfo = malloc(sizeof(struct endpointinfo));
    if (!einfo) {
      err = EEI_MEMORY;
      goto out_err;
    }
    memset(einfo, 0, sizeof(struct endpointinfo));
    
    _HIP_DEBUG("*** %p %p\n", einfo, previous_einfo);

    HIP_ASSERT(einfo); /* 1 */

    /* Allocate and fill the HI. Note that here we are assuming that the
       endpoint is really a HIT. The following assertion checks that we are
       dealing with a HIT. Change the memory allocations and other code when
       HIs are really supported. */
    HIP_ASSERT(hi_str_len == 4 * 8 + 7 * 1);

    einfo->ei_family = PF_HIP;
    einfo->ei_endpointlen = sizeof(struct endpoint_hip);
    einfo->ei_endpoint = malloc(einfo->ei_endpointlen);
    if (!einfo->ei_endpoint) {
      err = EEI_MEMORY;
      HIP_ERROR("Could not allocate memory for endpoint\n");
      goto out_err;
    }

    /* alias to avoid silly casting */
    endpoint_hip = (struct endpoint_hip *) einfo->ei_endpoint;

    endpoint_hip->family = PF_HIP;
    endpoint_hip->length = einfo->ei_endpointlen;
    endpoint_hip->flags = HIP_ENDPOINT_FLAG_HIT; /* HIs not yet supported */

    if (inet_pton(AF_INET6, hi_str, &endpoint_hip->id.hit) <= 0) {
      HIP_ERROR("Failed to convert string %s to HIT\n", hi_str);
      err = EEI_FAIL;
      goto out_err;
    }

    HIP_DEBUG("hi str: %s\n", hi_str);
    HIP_HEXDUMP("peer HIT: ", &endpoint_hip->id.hit, sizeof(struct in6_addr));

    HIP_ASSERT(einfo && einfo->ei_endpoint); /* 2 */

    /* "Clone" the result of getaddrinfo into the einfo. Note that the addrlist
       member in the einfo is statically allocated. */
    memcpy(&einfo->ei_addrlist, ai_res, sizeof(struct addrinfo));

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

  HIP_ASSERT(!err);
  return err;

 out_err:

  /* Free the first element from the addrinfo linked list. The list must be
     terminated with NULL to prevent freeaddrinfo from freeing also the
     other elements. The first element is freed here because otherwise it
     will lost forever (einfo was cloned above).
   */
  if (ai_res) {
    ai_res->ai_next = NULL;
    freeaddrinfo(ai_res);
  }

  if (hosts)
    err = fclose(hosts);

  /* Free all of the reserved memory on error */
  if (err) {
    /* Assertions 1, 2 and 3: einfo has not been linked to *res and
       it has to be freed separately. In English: free einfo only
       if it has not been linked into the *res list */
    if (einfo && previous_einfo != einfo) {
      if (einfo->ei_endpoint) /* Assertion 2: endpoint has been allocated */
	free(einfo->ei_endpoint);
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
  if (hints->ei_family != PF_HIP) {
    err = -EEI_FAMILY;
    HIP_ERROR("Only HIP is currently supported\n");
    goto err_out;
  }

  memcpy(&modified_hints, hints, sizeof(struct endpointinfo));
  modified_hints.ei_addrlist.ai_flags |= AI_HIP_NATIVE; 

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
