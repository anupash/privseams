#ifndef ESP_DECRYPT_H
#define ESP_DECRYPT_H

//#include "conntrack.h"
#include "crypto.h"
#include "firewall_defines.h"

/*struct hip_esp_packet {
	int packet_length;
	struct hip_esp * esp_data;
	struct hip_esp_tail * esp_tail;
};

struct hip_esp {
	uint32_t esp_spi;
    uint32_t esp_seq;
};

struct hip_esp_tail {
	 uint8_t esp_padlen;
     uint8_t esp_next;
};*/


int decrypt_packet(const struct in6_addr * dst_addr, 
	struct esp_tuple *esp_tuple, struct hip_esp_packet * esp);


#endif //ESP_DECRYPT_H
