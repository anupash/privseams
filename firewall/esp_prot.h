#ifndef ESP_PROT_H_
#define ESP_PROT_H_

#include "hashchain_store.h"
#include "user_ipsec_sadb.h"

int esp_prot_init(void);
int esp_prot_set_sadb(hip_sa_entry_t *entry, uint8_t esp_prot_transform,
		unsigned char *esp_prot_anchor, int direction);
int add_esp_prot_hash(unsigned char *out_hash, int *out_length, hip_sa_entry_t *entry);
int verify_esp_prot_hash(hip_sa_entry_t *entry, unsigned char *hash_value);
hash_chain_t * esp_prot_get_corresponding_hchain(unsigned char *hchain_anchor,
		uint8_t transform);
int get_esp_data_offset(hip_sa_entry_t *entry);
int esp_prot_ext_maintainance(hip_sa_entry_t *entry);

#endif /*ESP_PROT_H_*/
