#ifndef EXT_ESP_PROT_COMMON_H_
#define EXT_ESP_PROT_COMMON_H_

/* IDs for all supported transforms
 *
 * @note If you change these, make sure to also change the helper defines
 *       NUM_* and to set up hash_functions[] and hash_lengths[][] in esp_prot.h
 *       accordingly. Ensure to add new hash-functions in the end of the transforms
 *       list and pay attention to the order of the hash-lengths for each function.
 */
#define ESP_PROT_TFM_UNUSED			0
#define ESP_PROT_TFM_SHA1_8			1
#define ESP_PROT_TFM_SHA1_16		2
#define ESP_PROT_TFM_SHA1_20		3
#define ESP_PROT_TFM_MD5_8			4
#define ESP_PROT_TFM_MD5_16			5

// TODO remove after test
#define NUM_TRANSFORMS				1
#define NUM_HASH_FUNCTIONS			1
#define NUM_HASH_LENGTHS			1

#if 0
 /**** helper defines for the index boundaries of the static arrays defined below ****/

/* When adding a new transform, make sure to also add it in esp_prot_common.h.
 * Ensure to add new hash-functions in the end of hash_functions[] and keep the
 * same order of the hash-lengths in hash_lengths[][] as in the define list for the
 * transforms in esp_prot_common.h. */

/* for transforms array, ESP_PROT_TFM_UNUSED is not counted here */
#define NUM_TRANSFORMS				5
/* for first dimension of hash_lengths[][] */
#define NUM_HASH_FUNCTIONS			2
/* for second dimension of hash_lengths[][] */
#define NUM_HASH_LENGTHS			3
#endif

static const hash_function_t hash_functions[] = {SHA1};
static const int hash_lengths[][] = {{8}};

#if 0
static const hash_function_t hash_functions[] = {SHA1, MD5};
static const int hash_lengths[][] = {{8, 16, 20}, {8, 16, 0}};
#endif

// TODO remove, only there for compatibility with old approach
#define ESP_PROT_TRANSFORM_UNUSED		0
#define ESP_PROT_TRANSFORM_DEFAULT		1
static const int esp_prot_transforms[2] = {0, 8};

#endif /*EXT_ESP_PROT_COMMON_H_*/
