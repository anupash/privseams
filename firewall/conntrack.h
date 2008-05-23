#ifndef CONNTRACK_H
#define CONNTRACK_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>

#include "debug.h"
#include "firewall_defines.h"
#include "esp_decrypt.h"
#include "rule_management.h"
#include "misc.h"
#include "hadb.h"
#include "pk.h"


/*-------------- CONNECTION TRACKING ------------*/
enum{
  ORIGINAL_DIR,
  REPLY_DIR,
    };

enum{
  STATE_NEW,
  STATE_ESTABLISHED,
  STATE_ESTABLISHING_FROM_UPDATE,
  STATE_CLOSING
};

extern int hip_proxy_status;


void print_data(struct hip_data * data);
int filter_esp_state(const struct in6_addr * dst_addr, 
		     struct hip_esp * esp, 
		    const struct rule * rule);
int filter_state(const struct in6_addr * ip6_src,
		 const struct in6_addr * ip6_dst, 
		 struct hip_common * buf, 
		 const struct state_option * rule, 
		 int);
void conntrack(const struct in6_addr * ip6_src,
	       const struct in6_addr * ip6_dst, 
	       struct hip_common * buf);
int verify_packet_signature(struct hip_host_id * hi, 
			    struct hip_common * common);

int add_esp_decryption_data(const struct in6_addr * hit_s, 
			    const struct in6_addr * hit_r, const struct in6_addr * dst_addr, 
			    uint32_t spi, int dec_alg, int auth_len, int key_len, 
			    struct hip_crypto_key	* dec_key);
                     
int remove_esp_decryption_data(const struct in6_addr * addr, uint32_t spi);


void init_timeout_checking(long int timeout_val);
#endif
