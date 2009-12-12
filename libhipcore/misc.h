/**@file
#include "hit_to_ip.h"
 * A header file for misc.c
 *
 * @author Miika Komu
 * @author Mika Kousa
 * @author Bing Zhou
 * @note   Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @see    misc.h
 */
#ifndef HIP_MISC_H
#define HIP_MISC_H

#ifdef __KERNEL__
#  include "usercompat.h"
#  include <linux/list.h>
#else
#  include "kerncompat.h"
#  include "hidb.h"
#endif /* __KERNEL__ */

#include "registration.h"
#include "libhipcore/utils.h"
#include "icomm.h"
#include "lutil.h"

#ifdef CONFIG_HIP_LIBHIPTOOL
#  include "hipconf.h"
#endif /* CONFIG_HIP_LIBHIPTOOL */

#ifndef HOST_NAME_MAX
# define HOST_NAME_MAX 64
#endif

#define HOST_ID_FILENAME_MAX_LEN 256

/* system/bin for Android */
#define HIP_DEFAULT_EXEC_PATH "/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin:/system/bin"

#define HIP_ID_TYPE_HIT     1
#define HIP_ID_TYPE_LSI     2

typedef struct _hip_hosts_entry
{
        hip_hit_t hit;
        hip_lsi_t lsi;
        char *hostname;
} hip_hosts_entry;

struct hip_rsa_keylen {
	int e_len;
	int e;
	int n;
};

int hip_sockaddr_is_v6_mapped(struct sockaddr *sa);

static inline int ipv4_addr_cmp(const struct in_addr *a1,
				const struct in_addr *a2)
{
	return memcmp((const char *) a1, (const char *) a2,
		      sizeof(struct in_addr));
}

static inline void ipv4_addr_copy(struct in_addr *a1,
				  const struct in_addr *a2)
{
	memcpy((char *) a1, (const char *) a2, sizeof(struct in_addr));
}

static inline int ipv6_addr_cmp(const struct in6_addr *a1,
				const struct in6_addr *a2)
{
	return memcmp((const char *) a1, (const char *) a2,
		      sizeof(struct in6_addr));
}

static inline void ipv6_addr_copy(struct in6_addr *a1,
				  const struct in6_addr *a2)
{
	memcpy((char *) a1, (const char *) a2, sizeof(struct in6_addr));
}

static inline int ipv6_addr_any(const struct in6_addr *a)
{
	return ((a->s6_addr32[0] | a->s6_addr32[1] | 
		 a->s6_addr32[2] | a->s6_addr32[3] ) == 0); 
}
int hip_opportunistic_ipv6_to_hit(const struct in6_addr *ip, 
				  struct in6_addr *hit, int hit_type);

static inline void hip_copy_in6addr_null_check(struct in6_addr *to, struct in6_addr *from) {
	HIP_ASSERT(to);
	if (from)
		ipv6_addr_copy(to, from);
	else
		memset(to, 0, sizeof(*to));
}

static inline void hip_copy_inaddr_null_check(struct in_addr *to, struct in_addr *from) {
	HIP_ASSERT(to);
	if (from)
		memcpy(to, from, sizeof(*to));
	else
		memset(to, 0, sizeof(*to));
}

int khi_encode(unsigned char *orig, int orig_len,
	       unsigned char *encoded,
	       int encoded_len);

int hip_dsa_host_id_to_hit(const struct hip_host_id *host_id,
			   struct in6_addr *hit, int hit_type);

/* Useless abstraction, goes to the same function anyway -- SAMU
   
   True that. Let's make this a static inline function and move it to the header
   file. It still remains as useless abstraction, but at least we eliminate the
   need for a call and return sequence. -Lauri 06.08.2008
*/
#ifndef __KERNEL__
static inline int hip_rsa_host_id_to_hit(const struct hip_host_id *host_id,
					 struct in6_addr *hit, int hit_type)
{
	return hip_dsa_host_id_to_hit(host_id, hit, hit_type);
}
#endif

int hip_host_id_to_hit(const struct hip_host_id *host_id,
		       struct in6_addr *hit, int hit_type);
int hip_private_dsa_host_id_to_hit(const struct hip_host_id *host_id,
				   struct in6_addr *hit,
				   int hit_type);
int hip_private_rsa_host_id_to_hit(const struct hip_host_id *host_id,
				   struct in6_addr *hit,
				   int hit_type);
int hip_private_host_id_to_hit(const struct hip_host_id *host_id,
			       struct in6_addr *hit, int hit_type);
int hip_timeval_diff(const struct timeval *t1, const struct timeval *t2,
		     struct timeval *result);
char* hip_in6_ntop(const struct in6_addr *in6, char *buf);
int hip_in6_ntop2(const struct in6_addr *in6, char *buf);
char* hip_hit_ntop(const hip_hit_t *hit, char *buf);
int hip_host_id_contains_private_key(struct hip_host_id *host_id);
u8 *hip_host_id_extract_public_key(u8 *buffer, struct hip_host_id *data);

int hip_lsi_are_equal(const hip_lsi_t *lsi1,
		      const hip_lsi_t *lsi2);
int hip_hit_is_bigger(const struct in6_addr *hit1,
		      const struct in6_addr *hit2);
int hip_hit_are_equal(const struct in6_addr *hit1,
		      const struct in6_addr *hit2);
void hip_xor_hits(struct in6_addr *res, 
		  const struct in6_addr *hit1, 
		  const struct in6_addr *hit2);

unsigned long hip_hash_hit(const void *hit);
unsigned long hip_hash_spi(const void *spi);
int hip_match_hit(const void *, const void *);
int convert_string_to_address_v4(const char *str, struct in_addr *ip);
int convert_string_to_address(const char *str, struct in6_addr *ip6);

hip_transform_suite_t hip_select_esp_transform(struct hip_esp_transform *ht);
hip_transform_suite_t hip_select_hip_transform(struct hip_hip_transform *ht);
int hip_auth_key_length_esp(int tid);
int hip_transform_key_length(int tid);
int hip_hmac_key_length(int tid);
int hip_enc_key_length(int tid);
int hip_birthday_success(uint64_t old_bd, uint64_t new_bd);
uint64_t hip_get_current_birthday(void);
int hip_serialize_host_id_action(struct hip_common *msg, int action, int anon,
				 int use_default, const char *hi_fmt,
				 const char *hi_file, int rsa_key_bits, int dsa_key_bits);
int hip_convert_hit_to_str(const hip_hit_t *hit, const char *prefix, char *str);

int maxof(int num_args, ...);

int addr2ifindx(struct in6_addr *local_address);
void get_random_bytes(void *buf, int n);

#ifndef __KERNEL__
int hip_build_digest(const int type, const void *in, int in_len, void *out);
int dsa_to_dns_key_rr(DSA *dsa, unsigned char **buf);
int rsa_to_dns_key_rr(RSA *rsa, unsigned char **rsa_key_rr);
#endif
void *hip_cast_sa_addr(const struct sockaddr* sa); 
int hip_sockaddr_len(const void *sockaddr);
int hip_sa_addr_len(void *sockaddr);
int hip_create_lock_file(char *filename, int killold);
int hip_remove_lock_file(char *filename);

void hip_addr_to_sockaddr(struct in6_addr *addr, struct sockaddr_storage *sa);

uint64_t hip_solve_puzzle(void *puzzle, struct hip_common *hdr, int mode);
int hip_solve_puzzle_m(struct hip_common *out, struct hip_common *in, hip_ha_t *entry);
int hip_create_lock_file(char *filename, int killold);

/**
 * Converts a string to lowercase. Converts parameter @c from string to a
 * lowercase string and places the result in @c to. All alphabetic (isalpha())
 * characters are converted. Non-alphabetic are copied from source buffer
 * @c from to target buffer @c to without conversion.
 *
 * @param  to    a target buffer where to put the converted string
 * @param  from  a source buffer which to convert.
 * @param  count number of characters in @c from <b>including null
 *               termination</b>. Use strlen(from) + 1.
 * @return       -1 if @c count is zero or if @c to or @c from are NULL, zero
 *               otherwise.
 */ 
int hip_string_to_lowercase(char *to, const char *from, const size_t count);

/**
 * Checks whether a string consists only of digits (isdigit()).
 *
 * @param  string the string to check
 * @return        -1 if @c string is NULL or if the string has characters other
 *                than digits, zero otherwise.
 */ 
int hip_string_is_digit(const char *string);

void hip_get_rsa_keylen(const struct hip_host_id *host_id, struct hip_rsa_keylen *ret, int is_priv);

#ifndef __KERNEL__
RSA *hip_key_rr_to_rsa(const struct hip_host_id *host_id, int is_priv);
DSA *hip_key_rr_to_dsa(const struct hip_host_id *host_id, int is_priv);
#endif


int hip_get_random_hostname_id_from_hosts(char *filename,
					  char *hostname,
					  char *id_str);


int hip_trigger_bex(const struct in6_addr *src_hit, const struct in6_addr *dst_hit,
                    struct in6_addr *src_lsi, struct in6_addr *dst_lsi,
                    struct in6_addr *src_ip, struct in6_addr *dst_ip);
int hip_get_data_packet_header(const struct in6_addr *src_hit,
		const struct in6_addr *dst_hit, int payload, struct hip_common *msg);
int hip_map_first_id_to_hostname_from_hosts(const struct hosts_file_line *entry,
					    const void *arg,
					    void *result);
int hip_map_first_hostname_to_hit_from_hosts(const struct hosts_file_line *entry,
					     const void *arg,
					     void *result);
int hip_map_first_hostname_to_lsi_from_hosts(const struct hosts_file_line *entry,
					     const void *arg,
					     void *result);
int hip_map_first_hostname_to_ip_from_hosts(const struct hosts_file_line *entry,
					    const void *arg,
					    void *result);
int hip_for_each_hosts_file_line(const char *hosts_file,
				 int (*func)(const struct hosts_file_line *line,
					     const void *arg,
					     void *result),
				 void *arg, void *result);
int hip_map_lsi_to_hit_from_hosts_files(hip_lsi_t *lsi, hip_hit_t *hit);
int hip_map_hit_to_lsi_from_hosts_files(const hip_hit_t *hit, hip_lsi_t *lsi);
int hip_map_id_to_ip_from_hosts_files(hip_hit_t *hit, hip_lsi_t *lsi, struct in6_addr *ip);
int hip_map_lsi_to_hostname_from_hosts(hip_lsi_t *lsi, char *hostname);

/**
 * Get HIP local NAT UDP port.
 */
in_port_t hip_get_local_nat_udp_port();

/**
 * Get HIP peer NAT UDP port.
 */
in_port_t hip_get_peer_nat_udp_port();

/**
 * Set HIP local NAT UDP port.
 */
int hip_set_local_nat_udp_port(in_port_t port);

/**
 * Set HIP peer NAT UDP port.
 */
int hip_set_peer_nat_udp_port(in_port_t port);

char *hip_get_nat_username(void *buf, const struct in6_addr *hit);

HIP_HASHTABLE *hip_linked_list_init();

int hip_get_proto_info(in_port_t port_dest, char *proto);

int hip_get_bex_state_from_LSIs(hip_lsi_t *src_lsi,	hip_lsi_t *dst_lsi, 
		struct in6_addr *src_ip, struct in6_addr *dst_ip, 
		struct in6_addr *src_hit, struct in6_addr *dst_hit);

u16 ipv4_checksum(u8 protocol, u8 src[], u8 dst[], u8 data[], u16 len);

/* openSSL wrapper functions for base64 encoding and decoding */

unsigned char * base64_encode(unsigned char *, unsigned int);

#endif /* HIP_MISC_H */
