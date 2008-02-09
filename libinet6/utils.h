#ifndef _HIP_UTILS
#define _HIP_UTILS

#ifdef __KERNEL__
#  include <linux/un.h>
#  include <linux/in6.h>
#  include "usercompat.h"
#  include "protodefs.h"
#  include "state.h"
#  include "icomm.h"
#  include "ife.h"
#else
#  include "kerncompat.h"
#  include "sys/un.h"
#  include "protodefs.h"
#  include "stdlib.h"
#  include "list.h"
#endif

#define HIP_TMP_FNAME_TEMPLATE "/tmp/hip_XXXXXX"
#define HIP_TMP_FNAME_LEN strlen(HIP_TMP_FNAME_TEMPLATE)

/* mktemp results to a compiler warning - or actually in a host of warnings
 * since this function is called from tens of places.
 * 
 * warning: the use of `mktemp' is dangerous, better use `mkstemp' or `mkdtemp'
 *
 * Please fix it if you know it is safe to do so.
 * -Lauri 26.09.2007 14:43
 */
static int hip_tmpname(char *fname) {
	memcpy(fname, HIP_TMP_FNAME_TEMPLATE, HIP_TMP_FNAME_LEN);
	return (mkstemp(fname));
	/*
      if (mktemp(fname) == NULL)
		return -1;
	else
		return 0;
	*/
} 

/**
 * hip_tmpname_gui: 
 * Similar function to hip_tmpname, but it returns 0. This is needed in the
 * connhipd_init() function of the GUI.
 *
 * @param fname: pointer to the buffer to store the filename.
 *
 * @return 0 if the unique filename is correctly assigned; -1 on error.
 *
 * -Alberto
 */
static int hip_tmpname_gui(char *fname) {
	memcpy(fname, HIP_TMP_FNAME_TEMPLATE, HIP_TMP_FNAME_LEN);
	//return (mkstemp(fname));
        
	if (mktemp(fname) == NULL)
		return -1;
	else
		return 0;
        
} 

/*
 * HIP header and parameter related constants and structures.
 *
 */

typedef uint32_t hip_closest_prefix_type_t;

static int ipv6_addr_is_hit(const struct in6_addr *hit)
{
	hip_closest_prefix_type_t hit_begin;
	memcpy(&hit_begin, hit, sizeof(hip_closest_prefix_type_t));
	hit_begin = ntohl(hit_begin);
	hit_begin &= HIP_HIT_TYPE_MASK_INV;
	return (hit_begin == HIP_HIT_PREFIX);
}

struct hip_opp_blocking_request_entry
{
	hip_hit_t             peer_phit;
	struct sockaddr_in6   caller;
	hip_hit_t             our_real_hit;
	//hip_hit_t             peer_real_hit;
	//spinlock_t           	lock;
	//atomic_t             	refcnt;
	
	time_t                creation_time;
    struct in6_addr       peer_ip;
    struct in6_addr       our_ip;  
    uint8_t               proxy_flag; //0: normal connection, 1: connection through proxy
  
};

struct hip_opp_hit_pair {
	hip_hit_t real_hit;
	hip_hit_t pseudo_hit;
};

inline static int ipv6_addr_is_null(struct in6_addr *ip){
	return ((ip->s6_addr32[0] | ip->s6_addr32[1] | 
		 ip->s6_addr32[2] | ip->s6_addr32[3] ) == 0); 
}

static inline int hit_is_real_hit(const struct in6_addr *hit) {
	return ipv6_addr_is_hit(hit) && (hit->s6_addr32[3] != 0);
}

static inline int hit_is_opportunistic_hit(const struct in6_addr *hit){
	return ipv6_addr_is_hit(hit) && (hit->s6_addr32[3] == 0);
}

static inline int hit_is_opportunistic_hashed_hit(const struct in6_addr *hit){
	return hit_is_opportunistic_hit(hit);
}

static inline int hit_is_opportunistic_null(const struct in6_addr *hit){
	// return hit_is_opportunistic_hit(hit);
  return ((hit->s6_addr32[0] | hit->s6_addr32[1] |
	   hit->s6_addr32[2] | (hit->s6_addr32[3]))  == 0);
}

static inline void set_hit_prefix(struct in6_addr *hit)
{
	hip_closest_prefix_type_t hit_begin;
	memcpy(&hit_begin, hit, sizeof(hip_closest_prefix_type_t));
	hit_begin &= htonl(HIP_HIT_TYPE_MASK_CLEAR);
	hit_begin |= htonl(HIP_HIT_PREFIX);
	memcpy(hit, &hit_begin, sizeof(hip_closest_prefix_type_t));
}

/* IN6_IS_ADDR_V4MAPPED(a) is defined in /usr/include/netinet/in.h */

#define SET_NULL_HIT(hit)                           \
        { memset(hit, 0, sizeof(hip_hit_t));        \
          set_hit_prefix(hit) }

#define IPV4_TO_IPV6_MAP(in_addr_from, in6_addr_to)                       \
         {(in6_addr_to)->s6_addr32[0] = 0;                                \
          (in6_addr_to)->s6_addr32[1] = 0;                                \
          (in6_addr_to)->s6_addr32[2] = htonl(0xffff);                    \
         (in6_addr_to)->s6_addr32[3] = (uint32_t) ((in_addr_from)->s_addr);}

#define IPV6_TO_IPV4_MAP(in6_addr_from,in_addr_to)    \
       { ((in_addr_to)->s_addr) =                       \
          ((in6_addr_from)->s6_addr32[3]); }

#define IPV6_EQ_IPV4(in6_addr_a,in_addr_b)   \
       ( IN6_IS_ADDR_V4MAPPED(in6_addr_a) && \
	((in6_addr_a)->s6_addr32[3] == (in_addr_b)->s_addr)) 

#define HIT2LSI(a) ( 0x01000000L | \
                     (((a)[HIT_SIZE-3]<<16)+((a)[HIT_SIZE-2]<<8)+((a)[HIT_SIZE-1])))

/*
 * TRUE if a is from 1.0.0.0/8
 */
#define IS_LSI32(a) ((a & 0x000000FF) == 0x00000001)
/*
 * TRUE if a is from 127.0.0.0/8
 */
#define IS_IPV4_LOOPBACK(a) ((a & 0x000000FF) == 0x0000007F)

#define HIT_IS_LSI(a) \
        ((((__const uint32_t *) (a))[0] == 0)                                 \
         && (((__const uint32_t *) (a))[1] == 0)                              \
         && (((__const uint32_t *) (a))[2] == 0)                              \
         && IS_LSI32(((__const uint32_t *) (a))[3]))        

#ifndef MIN
#  define MIN(a,b)	((a)<(b)?(a):(b))
#endif

#ifndef MAX
#  define MAX(a,b)	((a)>(b)?(a):(b))
#endif

#endif /* _HIP_UTILS */

