#include "utils.h"

int ipv6_addr_is_hit(const struct in6_addr *hit)
{
	hip_closest_prefix_type_t hit_begin;
	memcpy(&hit_begin, hit, sizeof(hip_closest_prefix_type_t));
	hit_begin = ntohl(hit_begin);
	hit_begin &= HIP_HIT_TYPE_MASK_INV;
	return (hit_begin == HIP_HIT_PREFIX);
}

int ipv6_addr_is_teredo(const struct in6_addr *teredo)
{
	hip_closest_prefix_type_t teredo_begin;
	memcpy(&teredo_begin, teredo, sizeof(hip_closest_prefix_type_t));
	teredo_begin = ntohl(teredo_begin);
	teredo_begin &= HIP_TEREDO_TYPE_MASK_INV;
	return (teredo_begin == HIP_TEREDO_PREFIX);
}

int ipv6_addr_is_null(struct in6_addr *ip){
	return ((ip->s6_addr32[0] | ip->s6_addr32[1] | 
		 ip->s6_addr32[2] | ip->s6_addr32[3] ) == 0); 
}

int hit_is_real_hit(const struct in6_addr *hit) {
	return ipv6_addr_is_hit(hit) && (hit->s6_addr32[3] != 0);
}

int hit_is_opportunistic_hit(const struct in6_addr *hit){
	return ipv6_addr_is_hit(hit) && (hit->s6_addr32[3] == 0);
}

int hit_is_opportunistic_hashed_hit(const struct in6_addr *hit){
	return hit_is_opportunistic_hit(hit);
}

int hit_is_opportunistic_null(const struct in6_addr *hit){
	// return hit_is_opportunistic_hit(hit);
  return ((hit->s6_addr32[0] | hit->s6_addr32[1] |
	   hit->s6_addr32[2] | (hit->s6_addr32[3]))  == 0);
}

void set_hit_prefix(struct in6_addr *hit)
{
	hip_closest_prefix_type_t hit_begin;
	memcpy(&hit_begin, hit, sizeof(hip_closest_prefix_type_t));
	hit_begin &= htonl(HIP_HIT_TYPE_MASK_CLEAR);
	hit_begin |= htonl(HIP_HIT_PREFIX);
	memcpy(hit, &hit_begin, sizeof(hip_closest_prefix_type_t));
}

void set_lsi_pyyrefix(hip_lsi_t *lsi)
{
	hip_closest_prefix_type_t lsi_begin;
	memcpy(&lsi_begin, lsi, sizeof(hip_closest_prefix_type_t));
	lsi_begin &= htonl(HIP_LSI_TYPE_MASK_CLEAR);
	lsi_begin |= htonl(HIP_LSI_PREFIX);
	memcpy(lsi, &lsi_begin, sizeof(hip_closest_prefix_type_t));
}
