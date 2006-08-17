#ifndef _HIP_UTILS
#define _HIP_UTILS

/*
 * HIP header and parameter related constants and structures.
 *
 */


static int ipv6_addr_is_hit(const struct in6_addr *hit)
{
	hip_closest_prefix_type_t hit_begin;
	memcpy(&hit_begin, hit, sizeof(hip_closest_prefix_type_t));
	hit_begin = ntohl(hit_begin);
	hit_begin &= HIP_HIT_TYPE_MASK_INV;
	return (hit_begin == HIP_HIT_PREFIX);
}

struct hip_opp_blocking_request_entry {
  struct list_head     	next_entry;
  spinlock_t           	lock;
  atomic_t             	refcnt;

  struct in6_addr      	hash_key;       /* hit_our XOR hit_peer */
  struct in6_addr       peer_real_hit;
  struct sockaddr_un    caller;
};

inline static ipv6_addr_is_null(struct in6_addr *ip){
	return ((ip->s6_addr32[0] | ip->s6_addr32[1] | 
		 ip->s6_addr32[2] | ip->s6_addr32[3] ) == 0); 
}

static inline int create_new_socket(int type, int protocol)
{
  return socket(AF_INET6, type, protocol);
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
	//printf("*************** %x\n", *hit);
	memcpy(&hit_begin, hit, sizeof(hip_closest_prefix_type_t));
	//printf("*************** %x\n", hit_begin);
	hit_begin &= HIP_HIT_TYPE_MASK_CLEAR;
	//printf("*************** %x\n", hit_begin);
	hit_begin = htonl(hit_begin);
	hit_begin |= HIP_HIT_PREFIX;
	//printf("*************** %x\n", hit_begin);
	hit_begin = htonl(hit_begin);
	//printf("*************** %x\n", hit_begin);
	memcpy(hit, &hit_begin, sizeof(hip_closest_prefix_type_t));
	//printf("*************** %x\n", *hit);
}

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

#define IS_LSI32(a) ((a & 0xFF) == 0x01)

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

