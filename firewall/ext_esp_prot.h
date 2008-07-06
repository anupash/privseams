#ifndef ESP_PROT_EXT_H_
#define ESP_PROT_EXT_H_

#include "hashchain_store.h"
#include "ext_user_ipsec_sadb.h"

int esp_prot_ext_init(void);
int add_esp_prot_hash(unsigned char *out_hash, int *out_length, hip_sadb_entry *entry);
int verify_esp_prot_hash(hip_sadb_entry *entry, unsigned char *hash_value);
int esp_prot_get_corresponding_hchain(unsigned char *hchain_anchor, uint8_t transform,
		hash_chain_t *out_hchain);
int get_esp_data_offset(hip_sadb_entry *entry);
int esp_prot_ext_maintainance(hip_sadb_entry *entry);
int send_esp_protection_extension_to_hipd(void);
int send_anchor_list_update_to_hipd(uint8_t transform);
int send_next_anchor_to_hipd(unsigned char *anchor, uint8_t transform);

#endif /*ESP_PROT_EXT_H_*/
