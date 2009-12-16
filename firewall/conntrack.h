#ifndef CONNTRACK_H
#define CONNTRACK_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "firewall_defines.h"
#include "rule_management.h"
#include "common_types.h"


/*-------------- CONNECTION TRACKING ------------*/
enum{
  ORIGINAL_DIR,
  REPLY_DIR,
    };

extern int hip_proxy_status;
extern int esp_relay;

//void print_data(struct hip_data * data);
int filter_esp_state(const hip_fw_context_t * ctx, struct rule * rule, int not_used);
int filter_state(const struct in6_addr * ip6_src,
		 const struct in6_addr * ip6_dst,
		 struct hip_common * buf,
		 const struct state_option * option,
		 const int accept, hip_fw_context_t *ctx);
void conntrack(const struct in6_addr * ip6_src,
        const struct in6_addr * ip6_dst,
	    struct hip_common * buf, hip_fw_context_t *ctx);

int add_esp_decryption_data(const struct in6_addr * hit_s,
			    const struct in6_addr * hit_r, const struct in6_addr * dst_addr,
			    uint32_t spi, int dec_alg, int auth_len, int key_len,
			    struct hip_crypto_key	* dec_key);

int remove_esp_decryption_data(const struct in6_addr * addr, uint32_t spi);

void init_timeout_checking(long int timeout_val);

struct esp_tuple * find_esp_tuple(const SList * esp_list, uint32_t spi);

#endif
