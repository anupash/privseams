/*
 * common_defines.h
 *
 * Author: Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#ifndef COMMON_DEFINES_H_
#define COMMON_DEFINES_H_

/* maximum packet size of a packet to be sent on the wire */
#define MAX_PACKET_SIZE		1500

/* see bug id 595 */
#define MIN_HIP_MTU			1280

/* max. ESP padding as defined in RFC ???
 *
 * @note this allows to hide the actual payload length */
#define MAX_ESP_PADDING		255
/* this is the the max. ESP padding as needed by the cipher
 *
 * @note calculated as max. block-size - 1 */
#define CIPHER_ESP_PADDING	AES_BLOCK_SIZE - 1
/* change this if you want to use another padding */
#define ESP_PADDING			CIPHER_ESP_PADDING

/* overhead added by encapsulating the application packet in
 * an ESP packet
 *
 * @note ESP payload includes app's packet starting at transport layer
 *       -> transport layer header is part of MTU
 * @note additional space for possible IP4 -> IPv6 conversion, UDP encapsulation,
 *       ESP header, max. initialization vector for a cipher, max. allowed padding,
 *       ESP tail, ESP authentication part */
#define BEET_OVERHEAD		sizeof(struct ip6_hdr) - sizeof(struct ip) \
							+ sizeof(struct udphdr) + sizeof(struct hip_esp) \
							+ AES_BLOCK_SIZE + ESP_PADDING \
							+ sizeof(struct hip_esp_tail) + EVP_MAX_MD_SIZE
/* maximum allowed packet size coming from the application */

#define HIP_MTU				MAX_PACKET_SIZE - (BEET_OVERHEAD)

#define HIP_HIT_DEV_MTU		HIP_MTU >= MIN_HIP_MTU ? HIP_MTU : MIN_HIP_MTU


/*********** ESP structures *************/

struct hip_esp
{
	uint32_t esp_spi;
	uint32_t esp_seq;
} __attribute__ ((packed));

struct hip_esp_tail
{
	 uint8_t esp_padlen;
     uint8_t esp_next;
};

#endif /* COMMON_DEFINES_H_ */
