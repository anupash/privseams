#include "ipsec_userspace_api.h"

/* struct sockaddr {
 *        unsigned short sa_family;
 *      char sa_data[14];
 *
 * */






static __u16 hit_magic_value(void *sockaddr_src_hit, void *sockaddr_dst_hit)
{
	__u16 hit_magic_value;

	__u16 sa_src_hit_magic;
	__u16 sa_dst_hit_magic;
	
	struct sockaddr *sa_src_hit = (struct sockaddr *) sockaddr_src_hit;
 	struct sockaddr *sa_dst_hit = (struct sockaddr *) scokaddr_dst_hit;


	struct in_addr *in_addr_src = NULL;
	struct in6_addr *in6_addr_src = NULL;
	
	struct in_addr *in_addr_dst = NULL;
	struct in6_addr *in6_addr_dst = NULL;




	
	switch(sa_src_hit->sa_family) {

	case AF_INET:
		in_addr_src =  (struct in_addr *) hip_cast_sa_addr(sockaddr_src_hit);
		sa_src_hit_magic = in_addr_src->s_addr; /*  unsigned long */

	case AF_INET6:
		in6_addr_src = (struct in6_addr *) hip_cast_sa_addr(sockaddr_src_hit);
		in6_addr_src->s6_addr;   /* u_int8_t  s6_addr[16];  IPv6 address */ 


	}



	switch(sa_dst_hit->sa_family) {

	case AF_INET:
		in_addr_dst = (struct in_addr *) hip_cast_sa_addr(scokaddr_dst_hit);
		

	case AF_INET6:

		in6_addr_dst = (struct in6_addr *) hip_cast_sa_addr(scokaddr_dst_hit);

   }	

	/* in order to get sockaddr_in or sockaddr_in6 address*/
	struct sockaddr_in *sa_src_hit_ret = hip_cast_sa_addr(sockaddr_src_hit);

	struct sockaddr_in *sa_dst_hit_ret =  hip_cast_sa_addr(sockaddr_dst_hit);

	switch(sa_src_hit_ret->);

      

         
	



  struct sockaddr *sa = (struct sockaddr *) sockaddr;
  void *ret;

  switch(sa->sa_family)  {
  case AF_INET:
    ret = &(((struct sockaddr_in *) sockaddr)->sin_addr);
    break;
  case AF_INET6:
    ret = &(((struct sockaddr_in6 *) sockaddr)->sin6_addr);
    break;
  default:
    ret = NULL;
  
  return ret;

}

}
 




uint32_t hip_userspace_ipsec_add_sa(struct in6_addr *saddr, struct in6_addr *daddr,
			      struct in6_addr *src_hit, struct in6_addr *dst_hit,
			      uint32_t *spi, int ealg,
			      struct hip_crypto_key *enckey,
			      struct hip_crypto_key *authkey,
			      int already_acquired,
			      int direction, int update,
			      int sport, int dport) {
	/* XX FIXME: TAO */


  __u16 hit_magic;

  struct sockaddr *inner_src, *inner_dst; /*HIT address -- inner address*/
  struct sockaddr *src, *dst; /* IP address*/

  __u32 ipsec_spi = (__u32) *spi; /*IPsec SPI*/
  __u32 ipsec_e_type = (__u32) ealg; /* encry*/
   
 
  



  /* ip6/ip4 (in6_addr) address conversion to sockddr */

  hip_addr_to_sockaddr(saddr, src); /* source ip address conversion*/
  hip_addr_to_sockaddr(daddr, dst); /* destination ip address conversion */
  hip_addr_to_sockaddr(src_hit, inner_src); /* source HIT conversion */
  hip_addr_to_sockaddr(dst_hit, inner_dst); /* destination HIT conversion */
  





  /* hit_magic is the 16-bit sum of the bytes of both HITs. 
 * the checksum is calculated as other Internet checksum, according to 
 * the HIP spec this is the sum of 16-bit words from the input data a 
 * 32-bit accumulator is used but the end result is folded into a 16-bit
 * sum
 */


*hip_cast_sa_addr(void *sockaddr)  


 // hit_magic = 

 

  /* a_type is for crypto parameters, but type is currently ignored  */



/* struct hip_crypto_key {
 *  char key[HIP_MAX_]
 *
 * }
 *
 *  
 *  */


/* struct hip_crypto_key *enckey ---> __u8 *e_key */
/* struct hip_crypto_key *authkey  ---> __u8 *a_key */




/* 
int hip_sadb_add(__u32 type, __u32 mode, struct sockaddr *inner_src,
    struct sockaddr *inner_dst, struct sockaddr *src, struct sockaddr *dst,
    __u16 port,
    __u32 spi, __u8 *e_key, __u32 e_type, __u32 e_keylen, __u8 *a_key,
    __u32 a_type, __u32 a_keylen, __u32 lifetime, __u16 hitmagic)

*/







}

int hip_userspace_ipsec_setup_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit,
				    struct in6_addr *src_addr,
				    struct in6_addr *dst_addr, u8 proto,
				    int use_full_prefix, int update) {
	/* XX FIXME: TAO */
}

void hip_userspace_ipsec_delete_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit, u8 proto,
				      int use_full_prefix) {
	/* XX FIXME: TAO */
}

int hip_userspace_ipsec_flush_all_policy() {
	/* XX FIXME: TAO */
}

int hip_userspace_ipsec_flush_all_sa() {
	/* XX FIXME: TAO */
}

uint32_t hip_userspace_ipsec_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit) {
	/* XX FIXME: TAO */
}

void hip_userspace_ipsec_delete_default_prefix_sp_pair() {
	/* XX FIXME: TAO */
}

int hip_userspace_ipsec_setup_default_sp_prefix_pair() {
	/* XX FIXME: TAO */
}
