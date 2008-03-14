#include "ipsec_userspace_api.h"

 


/*
 * * function checksum_magic()
 * *
 * * Calculates the hitMagic value given two HITs.
 * * Note that since this is simple addition, it doesn't matter
 * * which HIT is given first, and the one's complement is not
 *   * taken.
 *    */

__u16 checksum_magic(const hip_hit *i, const hip_hit *r)

{
	int count;
	unsigned long sum = 0;
	unsigned short *p; /* 16-bit */
	
/* 
 * 	 * this checksum algorithm can be found 
 * 	 * in RFC 1071 section 4.1, pseudo-header
 * 	* from RFC 2460
 * */

	/* one's complement sum 16-bit words of data */
	/* sum initiator's HIT */
	count = HIT_SIZE;
	p = (unsigned short*) i;
	while (count > 1)  {
		sum += *p++;
		count -= 2;
	}
	/* sum responder's HIT */
	count = HIT_SIZE;
	p = (unsigned short*) r;
	while (count > 1)  {
		sum += *p++;
		count -= 2;
	}

	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);

	HIP_DEBUG("hitMagic checksum over %d bytes: 0x%x\n",
	    2*HIT_SIZE, (__u16)sum);
	
	/* don't take the one's complement of the sum */
	return((__u16)sum);
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
  __u32 ipsec_e_type = (__u32) ealg; /* encryption type */
  __u32 ipsec_a_type = ipsec_e_type; /* authentication type is equal to encryption type */

  __u8 *ipsec_e_key; 
  __u8 *ipsec_a_key;

  __u32 ipsec_e_keylen = HIP_MAX_KEY_LEN; 
  __u32 ipsec_a_keylen = HIP_MAX_KEY_LEN;


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



  hit_magic = checksum_magic((hip_hit *) src_hit->s6_addr, (hip_hit *) dst_hit->s6_addr);
 

 

  /* a_type is for crypto parameters, but type is currently ignored  */



  /* struct hip_crypto_key {
   *  char key[HIP_MAX_KEY_LEN]
   *  }
   *  HIP_MAX_KEY_LEN 32 // max. draw: 256 bits!
   */
  
  /* struct hip_crypto_key *enckey ---> __u8 *e_key */
  /* struct hip_crypto_key *authkey  ---> __u8 *a_key */
  
  ipsec_e_key = (__u8 *) enckey->key;
  ipsec_a_key = (__u8 *) authkey->key;
  
  
  
  
  /* 
     int hip_sadb_add(__u32 type, __u32 mode, struct sockaddr *inner_src,
     struct sockaddr *inner_dst, struct sockaddr *src, struct sockaddr *dst,
     __u16 port,
     __u32 spi, __u8 *e_key, __u32 e_type, __u32 e_keylen, __u8 *a_key,
     __u32 a_type, __u32 a_keylen, __u32 lifetime, __u16 hitmagic)
     
  */
  
  /* looking at the usermode code, it may be that the lifetime is stored in
   * the hip_sadb_entry but never used. It is supposed to be the value in
   * seconds after which the SA expires but I don't think this is
   * implemented. It is a preserved field from the kernel API, from the
   * PFKEY messages.
   *
   * */
  
  /* Here just give a value 100 to lifetime*/
  
  hip_sadb_add(TYPE_USERSPACE_IPSEC, IPSEC_MODE, inner_src, inner_dst, src, dst,
	       (__u16) dport, ipsec_spi, ipsec_e_key, ipsec_e_type, ipsec_e_keylen,ipsec_a_key, 
	       ipsec_a_type, ipsec_a_keylen, 100 , hit_magic);
  
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
