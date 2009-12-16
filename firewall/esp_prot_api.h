/**
 * API for the TPA functionality
 *
 * Description:
 *
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef ESP_PROT_API_H_
#define ESP_PROT_API_H_

#include "esp_prot_defines.h"
#include "user_ipsec_sadb.h"

/* maps from the transform_id defined above to the hash-function id
 * and hash length id
 *
 * NOTE: this ensures, we don't use uninitialized
 *       (hash_function, hash_length)-combinations in the array
 */
typedef struct esp_prot_tfm
{
	int is_used; /* indicates if the transform is configured */
	int hash_func_id; /* index of the hash function used by the transform */
	int hash_length_id; /* index of the hash length used by the transform */
} esp_prot_tfm_t;


extern long token_transform;
extern long num_parallel_hchains;
extern long ring_buffer_size;
extern long num_linear_elements;
extern long num_random_elements;
extern long hash_length;
extern long hash_structure_length;
extern long num_hchains_per_item;
extern long num_hierarchies;
extern double refill_threshold;
extern double update_threshold;

extern int hash_lengths[NUM_HASH_FUNCTIONS][NUM_HASH_LENGTHS];
extern hash_function_t hash_functions[NUM_HASH_FUNCTIONS];


int esp_prot_init(void);
int esp_prot_uninit(void);
int esp_prot_sa_entry_set(hip_sa_entry_t *entry, const uint8_t esp_prot_transform,
		const uint32_t hash_item_length, const uint16_t esp_num_anchors,
		unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH], const int update);
void esp_prot_sa_entry_free(hip_sa_entry_t *entry);
int esp_prot_cache_packet_hash(unsigned char *esp_packet, const uint16_t esp_length, hip_sa_entry_t *entry);
int esp_prot_add_hash(unsigned char *esp_packet, int *out_length, hip_sa_entry_t *entry);
int esp_prot_verify_hchain_element(const hash_function_t hash_function, const int hash_length,
		unsigned char *active_anchor, const unsigned char *next_anchor,
		const unsigned char *hash_value, const int tolerance, const unsigned char *active_root,
		const int active_root_length, const unsigned char *next_root, const int next_root_length);
int esp_prot_verify_htree_element(const hash_function_t hash_function, const int hash_length,
		const uint32_t hash_tree_depth, const unsigned char *active_root, const unsigned char *next_root,
		const unsigned char *active_uroot, const int active_uroot_length, const unsigned char *next_uroot,
		const int next_uroot_length, const unsigned char *hash_value);
esp_prot_tfm_t * esp_prot_resolve_transform(const uint8_t transform);
hash_function_t esp_prot_get_hash_function(const uint8_t transform);
int esp_prot_get_hash_length(const uint8_t transform);
int esp_prot_get_data_offset(const hip_sa_entry_t *entry);
int esp_prot_sadb_maintenance(hip_sa_entry_t *entry);

#endif /*ESP_PROT_API_H_*/
