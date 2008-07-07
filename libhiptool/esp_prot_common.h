#ifndef EXT_ESP_PROT_COMMON_H_
#define EXT_ESP_PROT_COMMON_H_

// the transforms used by esp protection extension
#define ESP_PROT_TRANSFORM_UNUSED		 0
#define ESP_PROT_TRANSFORM_DEFAULT		 1

// default length of the hash function output used in the chain
#define DEFAULT_HASH_LENGTH 8 // (in bytes)

#define DEFAULT_VERIFY_WINDOW 10

// (hash, salt)-length for the respective transform in bytes
static const int esp_prot_transforms[2] = {0, DEFAULT_HASH_LENGTH};

#endif /*EXT_ESP_PROT_COMMON_H_*/
