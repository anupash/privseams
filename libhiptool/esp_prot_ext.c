#include "esp_prot_ext.h"

int esp_prot_ext_init()
{
	int err = 0;
	
	HIP_DEBUG("intializing the hash-chain stores...\n");
				
	/***** init the hash-chain store *****/
	int hc_element_lengths[] = {HC_LENGTH_STEP1};
	
	HIP_IFE(hip_hchain_store_init(hc_element_lengths, 1), -1);
	
	HIP_IFE(hip_hchain_bexstore_set_item_length(HC_LENGTH_BEX_STORE), -1)
	
	// ... and fill it with elements
	HIP_IFE(hchain_store_maintainance(), -1);
	
  out_err:
  	return err;
}

int add_esp_prot_hash(hip_sadb_entry *entry, unsigned char *out_hash, int *out_length)
{
	int err = 0;
	
	// first determine hash length
	if (entry->active_hchain->transform > ESP_PROT_TRANSFORM_UNUSED)
	{
		*out_length = esp_prot_transforms[]
	}
	
	HIP_DEBUG("adding hash chain element to outgoing packet...\n");
	hash_element = hchain_pop(entry->active_hchain);
	
	/* don't send anchor as it could be known to third party
	 * -> other end-host will not accept it
	 * -> get next element */
	if (!memcmp(hash_element->hash, entry->active_hchain->anchor_element->hash,
			hash_length))
	{	
		hash_element = hchain_pop(entry->active_hchain);
	}
	
	// copy the hash value into the buffer
	memcpy(out_hash, hash_element->hash, out_length);
	
	// now do some maintainance operations
	esp_prot_ext_maintainance();
}

/* verifies received hchain-elements */
int verify_esp_prot_hash(hip_sadb_entry *entry, unsigned char *hash_value)
{
	int hash_length = 0;
	// assume that the hash is ok
	int err = 0;
	
	HIP_DEBUG("verifying hash chain element for incoming packet...\n");
	
	if (entry->active_anchor && entry->active_anchor->transform > ESP_PROT_TRANSFORM_UNUSED)
	{
		hash_length = esp_prot_transforms[entry->active_anchor->transform];
		
	} else
	{
		// no need to verify
		goto out_err;
	}
		
	if (hchain_verify(hash_item->hash, entry->active_anchor->hash,
		entry->tolerance, hash_length))
	{
		// this will allow only increasing elements to be accepted
		memcpy(entry->active_anchor, hash, hash_length);
		HIP_DEBUG("hash-chain element correct!\n");
		
	} else
	{
		if (entry->next_anchor && entry->next_anchor->transform > ESP_PROT_TRANSFORM_UNUSED)
		{
			hash_length = esp_prot_transforms[entry->next_anchor->transform];
			
		} else
		{
			// no need to verify
			goto out_err;
		}
		
		// check if there was an implicit change to the next hchain
		if (hchain_verify(sent_hc_element, entry->next_anchor->hash,
				entry->tolerance, hash_length))
		{
			memcpy(entry->active_anchor, entry->next_anchor, hash_length);
			entry->active_anchor->transform = entry->next_anchor->transform;
			memset(entry->next_anchor, 0, sizeof(esp_hash_item));
			
		} else
		{
			// handle incorrect elements -> drop packet
			HIP_DEBUG("INVALID hash-chain element!\n");
			
			err = 1;
			goto out_err;
		}
	}
	
  out_err:
    return err;
}

int esp_prot_ext_maintainance()
{
	/* make sure the next hash-chain is set up before the active one
	 * depletes */
	if (!entry->next_hchain && entry->active_hchain->remaining
				<= entry->active_hchain->hchain_length * REMAIN_THRESHOLD)
	{
		// set next hchain
		hip_hchain_store_get_hchain(HC_LENGTH_STEP1, entry->next_hchain);
		// issue UPDATE message to be sent by hipd
		send_next_anchor_to_hipd(entry->next_hchain);
		
		decreased_store_count = 1;
	}
	
	// activate next hchain if current one is depleted
	if (entry->next_hchain && entry->active_hchain->remaining == 0)
	{
		// this will free all linked elements in the hchain
		hchain_destruct(entry->active_hchain->hchain);
		HIP_DEBUG("changing to next_hchain\n");
		entry->active_hchain = entry->next_hchain;
		entry->next_hchain = NULL;
	}
	
	// check if we should refill the stores
	if (decreased_store_count)
	{
		err = hip_hchain_stores_refill();
		if (err < 0)
		{
			HIP_ERROR("error refilling the stores\n");
			goto out_err;
		} else if (err > 0)
		{
			// this means the bex store was updated
			HIP_DEBUG("sending anchor update...\n");
			send_anchor_list_update_to_hipd();
			
			err = 0;
		}
	}
}

/* this sends the prefered transform to hipd implicitely turning on
 * the esp protection extension there */
int send_esp_protection_extension_to_hipd()
{
	int err = 0;
	struct hip_common *msg = NULL;
	uint8_t transform = 0;
	
	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "alloc memory for adding sa entry\n");
	
	hip_msg_init(msg);
	
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_ESP_PROT_EXT_TRANSFORM, 0), -1, 
		 "build hdr failed\n");
	
	transform = ESP_PROT_TRANSFORM_DEFAULT;
	
	HIP_IFEL(hip_build_param_contents(msg, (void *)&transform, HIP_PARAM_UINT,
					  sizeof(uint8_t)), -1,
					  "build param contents failed\n");
	
	HIP_DEBUG("sending esp protection extension transform to hipd...\n");
	HIP_DUMP_MSG(msg);
	
	/* send msg to hipd and receive corresponding reply */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");
	
	HIP_DEBUG("send_recv msg succeeded\n");
	HIP_DEBUG("esp extension transform successfully set up\n");
	
 out_err:
	if (msg)
		free(msg);
	return err;
}

/* sends a list of all available anchor elements in the bex store
 * to the hipd, which then draws the element used in the bex from
 * this list */
int send_anchor_list_update_to_hipd()
{
	int err = 0;
	struct hip_common *msg = NULL;
	
	create_bexstore_anchors_message(msg);
	
	HIP_DUMP_MSG(msg);
		
	/* send msg to hipd and receive corresponding reply */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");
	
	HIP_DEBUG("send_recv msg succeeded\n");
	
 out_err:
	if (msg)
		free(msg);
	return err;
}

/* invoke an UPDATE message containing the next anchor element to be used */
int send_next_anchor_to_hipd(unsigned char *anchor)
{
	int err = 0;
	struct hip_common *msg = NULL;
	
	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "alloc memory for adding sa entry\n");
	
	hip_msg_init(msg);
	
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_IPSEC_NEXT_ANCHOR, 0), -1, 
		 "build hdr failed\n");
	
	HIP_DEBUG("anchor: %x \n", *anchor);
	HIP_IFEL(hip_build_param_contents(msg, (void *)anchor, HIP_PARAM_UINT,
					  sizeof(unsigned int)), -1,
					  "build param contents failed\n");
	
	HIP_DUMP_MSG(msg);
	
	/* send msg to hipd and receive corresponding reply */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");
	
	HIP_DEBUG("send_recv msg succeeded\n");
	
 out_err:
	if (msg)
		free(msg);
	return err;
}