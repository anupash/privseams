/** @file
 * A header file for misc.c
 *
 * @author Miika Komu
 * @author Mika Kousa
 * @author Bing Zhou
 * @note   Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @see    misc.h
 */
#ifndef HIP_LIB_CORE_MISC_H
#define HIP_LIB_CORE_MISC_H

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "hipd/hidb.h"

#include <string.h>
#include "hipd/registration.h"
#include "lib/core/prefix.h"
#include "icomm.h"
#include "lib/tool/lutil.h"

#ifdef CONFIG_HIP_LIBHIPTOOL
#  include "libhipconf/hipconf.h"
#endif /* CONFIG_HIP_LIBHIPTOOL */

#ifndef HOST_NAME_MAX
# define HOST_NAME_MAX 64
#endif

#ifdef CONFIG_HIP_OPENWRT
# define HIP_CREATE_FILE(x)     check_and_create_file(x, 0644)
#else
# define HIP_CREATE_FILE(x)     open((x), O_RDWR | O_CREAT, 0644)
#endif

/* system/bin for Android */
#define HIP_DEFAULT_EXEC_PATH "/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin:/system/bin"

struct hip_rsa_keylen {
    int e_len;
    int e;
    int n;
};

struct hip_hit_info {
    struct hip_lhi lhi;
    hip_lsi_t      lsi;
};

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
    return (a->s6_addr[0] | a->s6_addr[1] | a->s6_addr[2] | a->s6_addr[3] |
            a->s6_addr[4] |a->s6_addr[5] |a->s6_addr[6] |a->s6_addr[7] |
            a->s6_addr[8] |a->s6_addr[9] |a->s6_addr[10] |a->s6_addr[11] |
            a->s6_addr[12] |a->s6_addr[13] |a->s6_addr[14] |a->s6_addr[15]) == 0;
}

static inline void hip_copy_in6addr_null_check(struct in6_addr *to,
                                               struct in6_addr *from)
{
    HIP_ASSERT(to);
    if (from) {
        ipv6_addr_copy(to, from);
    } else {
        memset(to, 0, sizeof(*to));
    }
}

static inline void hip_copy_inaddr_null_check(struct in_addr *to,
                                              struct in_addr *from)
{
    HIP_ASSERT(to);
    if (from) {
        memcpy(to, from, sizeof(*to));
    } else {
        memset(to, 0, sizeof(*to));
    }
}

int khi_encode(unsigned char *orig, int orig_len,
               unsigned char *encoded,
               int encoded_len);

char *hip_in6_ntop(const struct in6_addr *in6, char *buf);
char *hip_hit_ntop(const hip_hit_t *hit, char *buf);
uint8_t *hip_host_id_extract_public_key(uint8_t *buffer, struct hip_host_id *data);

int hip_lsi_are_equal(const hip_lsi_t *lsi1,
                      const hip_lsi_t *lsi2);
int hip_hit_is_bigger(const struct in6_addr *hit1,
                      const struct in6_addr *hit2);
int hip_hit_are_equal(const struct in6_addr *hit1,
                      const struct in6_addr *hit2);

unsigned long hip_hash_hit(const void *hit);
int hip_match_hit(const void *, const void *);
int convert_string_to_address_v4(const char *str, struct in_addr *ip);
int convert_string_to_address(const char *str, struct in6_addr *ip6);

hip_transform_suite_t hip_select_esp_transform(struct hip_esp_transform *ht);
hip_transform_suite_t hip_select_hip_transform(struct hip_hip_transform *ht);
int hip_auth_key_length_esp(int tid);
int hip_transform_key_length(int tid);
int hip_hmac_key_length(int tid);
int hip_enc_key_length(int tid);
uint64_t hip_get_current_birthday(void);
int hip_convert_hit_to_str(const hip_hit_t *hit, const char *prefix, char *str);

int maxof(int num_args, ...);

int addr2ifindx(struct in6_addr *local_address);

uint64_t hip_solve_puzzle(void *puzzle, struct hip_common *hdr, int mode);
int hip_solve_puzzle_m(struct hip_common *out,
                       struct hip_common *in,
                       hip_ha_t *entry);
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

int hip_get_random_hostname_id_from_hosts(char *filename,
                                          char *hostname,
                                          char *id_str);

int hip_trigger_bex(const struct in6_addr *src_hit,
                    const struct in6_addr *dst_hit,
                    struct in6_addr *src_lsi,
                    struct in6_addr *dst_lsi,
                    struct in6_addr *src_ip,
                    struct in6_addr *dst_ip);

int hip_get_data_packet_header(const struct in6_addr *src_hit,
                               const struct in6_addr *dst_hit,
                               int payload,
                               struct hip_common *msg);

/**
 * Check if the given address is loopback.
 */
int hip_addr_is_loopback(struct in6_addr *addr);

HIP_HASHTABLE *hip_linked_list_init(void);

int hip_get_proto_info(in_port_t port_dest, char *proto);

int hip_get_bex_state_from_LSIs(hip_lsi_t *src_lsi,
                                hip_lsi_t *dst_lsi,
                                struct in6_addr *src_ip,
                                struct in6_addr *dst_ip,
                                struct in6_addr *src_hit,
                                struct in6_addr *dst_hit);

uint16_t ipv4_checksum(uint8_t protocol, void *s, void *d, void *c, uint16_t len);

/* openSSL wrapper functions for base64 encoding and decoding */

unsigned char *base64_encode(unsigned char *, unsigned int);

#endif /* HIP_LIB_CORE_MISC_H */
