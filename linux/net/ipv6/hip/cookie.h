#ifndef HIP_COOKIE_H
#define HIP_COOKIE_H

#include <linux/types.h>
#include <net/ipv6.h>
#include <net/hip.h>

#define HIP_R1DB_SIZE 10
#define HIP_PUZZLE_MAX_LIFETIME 60 /* in seconds */
#define HIP_R1TABLESIZE 3 /* precreate only this many R1s */
#define HIP_DEFAULT_COOKIE_K 10ULL

typedef enum { HIP_R1ESTATE_INVALID=0, HIP_R1ESTATE_VALID=1 } hip_r1estate_t;

struct hip_r1entry {
	struct hip_common *r1;
	uint32_t generation;
	uint64_t Ci;
	uint8_t Ck;
	uint8_t Copaque[3];
};

struct hip_r1db_entry{
	struct list_head   next_hit;

	atomic_t              refcnt;
	spinlock_t            r1e_lock;

	hip_r1estate_t        r1estate;
	struct in6_addr       hit;  /* The HIT we use for R1 precreation in this entry */
	struct hip_r1entry r1table[HIP_R1TABLESIZE];
};

typedef struct hip_r1db_entry HIP_R1E;

struct hip_common *hip_get_r1(struct in6_addr *ip_i, struct in6_addr *ip_r, struct in6_addr *hit);
int hip_init_r1(void);
void hip_uninit_r1(void);
void hip_init_r1db(void);
HIP_R1E *hip_allocate_r1db_entry(void);
int hip_precreate_r1(const struct in6_addr *src_hit);
int hip_verify_cookie(struct in6_addr *ip_i, struct in6_addr *ip_r, 
		      struct hip_common *hdr,
		      struct hip_solution *cookie, struct in6_addr *hit);
uint64_t hip_solve_puzzle(void *puzzle, struct hip_common *hdr, int mode);
int hip_verify_generation(struct in6_addr *ip_i, struct in6_addr *ip_r,
			  uint64_t birthday, struct in6_addr *hit);

void hip_r1_delete(HIP_R1E *entry);

/************* macros *****************/

#define hip_hold_r1db(r1e) do { \
	atomic_inc(&r1e->refcnt); \
        HIP_DEBUG("R1DB: %p, refcnt increased to: %d\n",rva, atomic_read(&r1e->refcnt)); \
} while(0) 

#define hip_put_r1db(r1e) do { \
	if (atomic_dec_and_test(&r1e->refcnt)) { \
                HIP_DEBUG("R1DB: %p, refcnt reached zero. Deleting...\n",r1e); \
		hip_r1_delete(r1e); \
	} else { \
                HIP_DEBUG("R1DB: %p, refcnt decremented to: %d\n", r1e, atomic_read(&r1e->refcnt)); \
        } \
} while(0) 

#define HIP_LOCK_R1DB(r1e) spin_lock(&r1e->r1e_lock)
#define HIP_UNLOCK_R1DB(r1e) spin_unlock(&r1e->r1e_lock)


#endif /* HIP_COOKIE_H */
