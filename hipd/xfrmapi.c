#include "xfrmapi.h"

// FIXME: implement wrappers to access the stuff in kernel over netlink

int hip_delete_sa(u32 spi, struct in6_addr *dst) {
	hip_netlink_send()
	//return 0;
}

uint32_t hip_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit) {
	return 0;
}

int hip_setup_sa(struct in6_addr *srchit, struct in6_addr *dsthit,
                 uint32_t *spi, int alg, void *enckey, void *authkey,
                 int already_acquired, int direction) {
	return 0;
}

void hip_finalize_sa(struct in6_addr *hit, u32 spi) {
	
}
