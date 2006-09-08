/*
 * 
 * 
 */


#include "esp_decrypt.h"

int decrypt_packet(const struct in6_addr * dst_addr, 
	struct esp_tuple *esp_tuple, struct hip_esp_packet * esp)
{
	int err = 0;
	int ret = 0;
		//uint32_t payload_len = esp->packet_length - esp_tuple->dec_data->auth_len;
		//esp->esp_tail = esp->esp_data + (s)
		char * enc;
		uint32_t esp_hdr_len;
		uint32_t auth_len;
		uint32_t enc_len, enc_len2;
		char * iv;
		char * key;
	uint32_t spi;
	uint32_t seq;

	spi = ntohl(esp->esp_data->esp_spi);
	seq = ntohl(esp->esp_data->esp_seq);

	HIP_DEBUG("Decrypting ESP packet: spi = %d, seq = %d\n", spi, seq);
	HIP_ASSERT(esp_tuple != NULL);
	HIP_ASSERT(esp_tuple->dec_data != NULL);
	if (esp_tuple->dec_data->dec_alg == HIP_ESP_3DES_SHA1) {
		
		
		HIP_DEBUG("Encryption algorithm 3DES with SHA1 authentication\n");
		 
		//enc = (char *)esp->esp_data + (sizeof(struct hip_esp)); 
		esp_hdr_len = sizeof(struct hip_esp) + sizeof(des_cblock);
		auth_len = esp_tuple->dec_data->auth_len; 
		enc_len = esp->packet_length - esp_hdr_len - auth_len; 
		//enc_len = esp->packet_length - sizeof(struct hip_esp) - auth_len;
		//iv = (char *)esp->esp_data + sizeof(struct hip_esp); 
		
		//HIP_IFEL(!(enc = (char *)malloc(enc_len)), -1, "Out of memory\n");
		//memcpy(enc, (char *)esp->esp_data + esp_hdr_len, enc_len); 
		//memcpy(enc, (char *)esp->esp_data + sizeof(struct hip_esp), enc_len); 
		enc = (char *)esp->esp_data + esp_hdr_len;
		
		HIP_IFEL(!(iv = (char *)malloc(/*sizeof(des_cblock)*/20)), -1, "Out of memory\n");
		memcpy(iv, (char *)esp->esp_data + sizeof(struct hip_esp), sizeof(des_cblock)); 
		 
		HIP_DEBUG("packet_len %d, esp_hdr_len %d, auth_len %d, data_len %d\n", esp->packet_length, esp_hdr_len, auth_len, enc_len);
		HIP_HEXDUMP("Encrypted data: \n", enc, enc_len); 
		 HIP_HEXDUMP("IV: \n", iv, sizeof(des_cblock)); 
		 
		 HIP_IFEL(!(key = (char *)malloc(esp_tuple->dec_data->key_len)), -1, "Out of memory\n");
		 memcpy(key, &esp_tuple->dec_data->dec_key, esp_tuple->dec_data->key_len);
		enc_len2 = enc_len; 
		 HIP_HEXDUMP("Key: \n", key, esp_tuple->dec_data->key_len); 
		
		
		//decrypt_3des((void *)enc, (const void *)iv, enc_len, (void *)key, esp_tuple->dec_data->key_len);
		 
		err =  hip_crypto_encrypted((void *)enc, (const void *)iv, 
			esp_tuple->dec_data->dec_alg, enc_len,
			 (void *)key, HIP_DIRECTION_DECRYPT);
		
		if (err < 0) {
			HIP_DEBUG("Decryption unsuccesfull\n");
		}
		else {
		 	HIP_DEBUG("Decryption succesfull!\n");
		 	//HIP_DEBUG("enc_len2 after decryption: %d\n", enc_len2);
		 	HIP_HEXDUMP("Decrypted data: \n", enc, enc_len);
		}
	}
	else {
		HIP_DEBUG("decrypt_packet: Encryption algorithm not supported!\n");
	}
	
out_err:	
	
	//if (enc) 
	//	free(enc);
	if (iv) 
		free(iv);
	if (key) 
		free(key);
		
	return err;	
}



