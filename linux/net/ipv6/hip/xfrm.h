int hip_delete_sp(int dir);
int hip_delete_sa(u32 spi, struct in6_addr *dst);
int hip_setup_sp(int dir);
uint32_t hip_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit);
int hip_setup_sa(struct in6_addr *srchit, struct in6_addr *dsthit,
                 uint32_t *spi, int alg, void *enckey, void *authkey,
                 int already_acquired, int direction);
void hip_finalize_sa(struct in6_addr *hit, u32 spi);

#ifdef __KERNEL__
/* BEET database entry struct and access functions to retrieve them. */
struct hip_xfrm_state {
	uint32_t             spi;
	hip_hit_t            hit_our;           /* The HIT we use with
						 * this host */
	hip_hit_t            hit_peer;          /* Peer's HIT */    
	struct in6_addr      preferred_address; /* preferred dst
						 * address to use when
						 * sending data to
						 * peer */
	int                  state;             /* state */
};

/* For inbound packet processing (SPI->(HITd,HITs) mapping) */
struct hip_xfrm_state * hip_xfrm_find(uint32_t spi);

/* For outbound packet processing (HITd->(SPI, IP) mapping */
struct hip_xfrm_state * hip_xfrm_find(struct in6_addr *dst_hit);

#endif


