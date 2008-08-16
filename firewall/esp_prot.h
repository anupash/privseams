#ifndef ESP_PROT_H_
#define ESP_PROT_H_

#include "hashchain_store.h"
#include "user_ipsec_sadb.h"

int esp_prot_init(void);
int esp_prot_set_sadb(hip_sa_entry_t *entry, uint8_t esp_prot_transform,
		unsigned char *esp_prot_anchor, int direction);
int add_esp_prot_hash(unsigned char *out_hash, uint16_t *out_length, hip_sa_entry_t *entry);
int verify_esp_prot_hash(hip_sa_entry_t *entry, unsigned char *hash_value);
hash_chain_t * esp_prot_get_corresponding_hchain(unsigned char *hchain_anchor,
		uint8_t transform);
int get_esp_data_offset(hip_sa_entry_t *entry);
int esp_prot_ext_maintainance(hip_sa_entry_t *entry);
int send_esp_protection_to_hipd(int active);
int send_anchor_list_update_to_hipd(uint8_t transform);
int send_next_anchor_to_hipd(unsigned char *anchor, uint8_t transform);

#endif /*ESP_PROT_H_*/
