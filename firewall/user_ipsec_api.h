/**
 * @file firewall/user_ipsec_api.h
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * This implementation provides the API for userspace IPsec.
 *
 * @brief API for the userspace IPsec functionality
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#ifndef HIP_FIREWALL_USER_IPSEC_API_H
#define HIP_FIREWALL_USER_IPSEC_API_H

#include <netinet/udp.h>
#include <openssl/evp.h>
#include "lib/core/misc.h"
#include "firewall_defines.h"

/* this is the maximum buffer-size needed for an userspace ipsec esp packet
 * including the initialization vector for ESP and the hash value of the
 * ESP protection extension */
#define MAX_ESP_PADDING     255
#define ESP_PACKET_SIZE     (HIP_MAX_PACKET + sizeof(struct udphdr) \
                             + sizeof(struct hip_esp) \
                             + AES_BLOCK_SIZE \
                             + MAX_ESP_PADDING \
                             + sizeof(struct hip_esp_tail) \
                             + EVP_MAX_MD_SIZE) \
                             + MAX_HASH_LENGTH

int userspace_ipsec_init(void);
int userspace_ipsec_uninit(void);
int hip_fw_userspace_ipsec_input(const hip_fw_context_t *ctx);
int hip_fw_userspace_ipsec_output(const hip_fw_context_t *ctx);

#endif /* HIP_FIREWALL_USER_IPSEC_API_H */
