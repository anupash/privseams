#ifndef GETENDPOINTINFO_H
#define GETENDPOINTINFO_H

#include <stdint.h>
#include <net/if.h>

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */


# define AI_HIP		0x0800	/* Return only HIT addresses */
# define AI_HIP_NATIVE	0x1000	/* For getaddrinfo internal use only  */
# define AI_RENDEZVOUS	XX_FIX_ME /* The address belongs to rendezvous */
# define AI_KERNEL_LIST 0x2000	/* Return the list of kernel addresses */
# define AI_CHK_KERNEL	0x4000	/* Check kernel list of addresses  */
# define AI_NODHT		0x8000	/* Check kernel list of addresses  */

/* XX TODO: begin these flags from where the AI_XX ends */
# define EI_PASSIVE		0x0001	/* Socket address is intended for `bind'.  */
# define EI_CANONNAME	0x0002	/* Request for canonical name.	*/
# define EI_ANON		XX_FIX_ME /* Return only anonymous endpoints */
# define EI_NOLOCATORS	XX_FIX_ME /* Do not resolve IP addresses */
# define EI_FALLBACK	XX_FIX_ME /* Fall back to plain TCP/IP is ok */

/* Error values for `getendpointinfo' function */

/* XX TODO: Are these really needed (they are the same with getaddrinfo)? */

/* # define EEI_BADFLAGS	  -1	/\* Invalid value for `ai_flags' field.	 *\/ */
# define EEI_NONAME	  -2	/* NAME or SERVICE is unknown.	*/
# define EEI_AGAIN	  -3	/* Temporary failure in name resolution.  */
# define EEI_FAIL	  -4	/* Non-recoverable failure in name res.	 */
# define EEI_NODATA	  -5	/* No address associated with NAME.	 */
# define EEI_FAMILY	  -6	/* `ai_family' not supported.  */
# define EEI_SOCKTYPE	  -7	/* `ai_socktype' not supported.	 */
# define EEI_SERVICE	  -8	/* SERVICE not supported for `ai_socktype'.	 */
# define EEI_ADDRFAMILY	  -9	/* Address family for NAME not supported.  */
# define EEI_MEMORY	  -10	/* Memory allocation failure.  */
# define EEI_SYSTEM	  -11	/* System error returned in `errno'.  */
/* # ifdef __USE_GNU */
#  define EEI_INPROGRESS  -100	/* Processing request in progress.	*/
#  define EEI_CANCELED	  -101	/* Request canceled.  */
#  define EEI_NOTCANCELED -102	/* Request not canceled.  */
#  define EEI_ALLDONE	  -103	/* All requests done.  */
#  define EEI_INTR	  -104	/* Interrupted by a signal.	 */
/* # endif */

/* The terminating \0 is excluded from STR_MAX */
#define GEPI_HI_STR_MAX		  "46"	/* Max number of chars in HI string	  */
#define GEPI_HI_STR_VAL_MAX		46
#define GEPI_FQDN_STR_MAX	   "255" /* Max number of chars in FQDN string */
#define GEPI_FQDN_STR_VAL_MAX	255

// TODO PF_MAX ??
#define PF_HIP			32		/* Host Identity Protocol */

int load_hip_endpoint_pem(const char *filename,
			  struct endpoint **endpoint);

int setmyeid(struct sockaddr_eid *my_eid,
	     const char *servname,
	     const struct endpoint *endpoint,
	     const struct if_nameindex *ifaces);

const char *gepi_strerror(int errcode);

/* Translate the name of a service name to a set of identifiers and locators.*/
extern int getendpointinfo (const char *,
			    const char *,
			    const struct addrinfo *,
			    struct addrinfo **);

/* Free `endpointinfo' structure ei including associated storage.  */
extern void free_endpointinfo (struct addrinfo *);

#endif /* GETENDPOINTINFO_H */
