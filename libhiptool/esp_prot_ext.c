#include "esp_prot_ext.h"
#include "firewall/firewall_defines.h"

// different hc_length in order not to spoil calculation time for short connections
#define HC_LENGTH_BEX_STORE 10
#define HC_LENGTH_STEP1 10
#define REMAIN_THRESHOLD 0.2

int esp_prot_ext_init()
{
	int err = 0;
	
	HIP_DEBUG("intializing the hash-chain stores...\n");
				
	/***** init the hash-chain store *****/
	int hc_element_lengths[] = {HC_LENGTH_STEP1};
	
	HIP_IFEL(hip_hchain_store_init(hc_element_lengths, 1), -1,
			"failed to initialize the hchain stores\n");
	
	HIP_IFEL(hip_hchain_bexstore_set_item_length(HC_LENGTH_BEX_STORE), -1,
			"failed to set item length for bex store\n");
	
	// ... and fill it with elements
	HIP_DEBUG("filling the hchain stores...\n");
	err = hip_hchain_stores_refill(esp_prot_transforms[ESP_PROT_TRANSFORM_DEFAULT]);
	if (err < 0)
	{
		HIP_ERROR("error refilling the stores\n");
		goto out_err;
	} else if (err > 0)
	{
		// this means the bex store was updated
		HIP_DEBUG("sending anchor list update to hipd...\n");
		HIP_IFEL(send_anchor_list_update_to_hipd(ESP_PROT_TRANSFORM_DEFAULT), -1,
				"unable to send anchor list update to hipd\n");
		
		err = 0;
	}
	
  out_err:
  	return err;
}

int add_esp_prot_hash(unsigned char *out_hash, int *out_length, hip_sadb_entry *entry)
{
	int err = 0;
	
	HIP_DEBUG("adding hash chain element to outgoing packet...\n");
	
	// first determine hash length
	*out_length = esp_prot_transforms[entry->active_transform];
	HIP_DEBUG("hash length is %i\n", *out_length);
	
	if (*out_length > 0)
	{
		/* put the hchain element directly in the provided buffer, no need to copy
		 * afterwards */
		HIP_IFEL(hchain_pop(entry->active_hchain, *out_length, out_hash), -1,
				"unable to retrieve hash element from hash-chain\n");
		
		/* don't send anchor as it could be known to third party
		 * -> other end-host will not accept it */
		if (!memcmp(out_hash, entry->active_hchain->anchor_element->hash,
				*out_length))
		{	
			// get next element
			HIP_IFEL(hchain_pop(entry->active_hchain, *out_length, out_hash), -1,
					"unable to retrieve hash element from hash-chain\n");
		}
		
		HIP_HEXDUMP("added esp protection hash: ", out_hash, *out_length);
		
		// now do some maintainance operations
		HIP_IFEL(esp_prot_ext_maintainance(entry), -1,
				"esp protection extension maintainance operations failed\n");
	}
	
  out_err:
    return err;
}

/* verifies received hchain-elements */
int verify_esp_prot_hash(hip_sadb_entry *entry, unsigned char *hash_value)
{
	int hash_length = 0;
	int err = 0;
	
	HIP_DEBUG("verifying hash chain element for incoming packet...\n");

	hash_length = esp_prot_transforms[entry->active_transform];
	HIP_DEBUG("hash length is %i\n", hash_length);
		
	// only verify the hash, if extension is switched on
	if (hash_length <= 0)
	{
		// extension might not be in use, no need to verify
		HIP_DEBUG("not expecting any hash-chain element\n");
		goto out_err;
	}
		
	if (hchain_verify(hash_value, entry->active_anchor,
			hash_length, entry->tolerance))
	{
		// this will allow only increasing elements to be accepted
		memcpy(entry->active_anchor, hash_value, hash_length);
		
		HIP_DEBUG("hash matches element in actice hash-chain\n");
		
	} else
	{
		// there might still be a chance that we have to switch to the next hchain
		hash_length = esp_prot_transforms[entry->next_transform];
			
		if (hash_length <= 0)
		{
			// next chain not set (yet), no need to verify
			goto out_err;
		}
		
		// check if there was an implicit change to the next hchain
		if (hchain_verify(hash_value, entry->next_anchor,
				hash_length, entry->tolerance))
		{
			HIP_DEBUG("hash matches element in next hash-chain\n");
			
			// beware, the hash lengths might differ between 2 different hchains
			if (entry->active_transform != entry->next_transform)
			{
				free(entry->active_anchor);
				entry->active_anchor = (unsigned char *)malloc(hash_length);
				entry->active_transform = entry->next_transform;
			}
			
			memcpy(entry->active_anchor, hash_value, hash_length);
			
			free(entry->next_anchor);
			entry->next_anchor = NULL;
			entry->next_transform = ESP_PROT_TRANSFORM_UNUSED;
			
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

int esp_prot_get_corresponding_hchain(unsigned char *hchain_anchor, uint8_t transform,
		hash_chain_t *out_hchain)
{
	int err = 0;
	out_hchain = NULL;
	
	HIP_IFEL(hip_hchain_bexstore_get_hchain(hchain_anchor, esp_prot_transforms[transform],
			out_hchain), -1, "unable to retrieve hchain from bex store\n");
	
  out_err:
  	return err;
}

int get_esp_data_offset(hip_sadb_entry *entry)
{
	return (sizeof(struct hip_esp) + esp_prot_transforms[entry->active_transform]);
}

int esp_prot_ext_maintainance(hip_sadb_entry *entry)
{
	int err = 0, decreased_store_count = 0;
	
	// first check the is extension is used
	if (entry->active_transform > ESP_PROT_TRANSFORM_UNUSED)
	{
		
		/* make sure that the next hash-chain is set up before the active one
		 * depletes */
		if (!entry->next_hchain && entry->active_hchain->remaining
					<= entry->active_hchain->hchain_length * REMAIN_THRESHOLD)
		{
			// set next hchain
			HIP_IFEL(hip_hchain_store_get_hchain(HC_LENGTH_STEP1, entry->next_hchain),
					-1, "unable to retrieve hchain from store\n");
			// issue UPDATE message to be sent by hipd
			HIP_IFEL(send_next_anchor_to_hipd(entry->next_hchain->anchor_element->hash,
					entry->active_transform), -1,
					"unable to send next anchor message to hipd\n");
			
			decreased_store_count = 1;
		}
		
		// activate next hchain if current one is depleted
		if (entry->next_hchain && entry->active_hchain->remaining == 0)
		{
			// this will free all linked elements in the hchain
			hchain_destruct(entry->active_hchain);
			
			HIP_DEBUG("changing to next_hchain\n");
			entry->active_hchain = entry->next_hchain;
			entry->next_hchain = NULL;
		}
		
		// check if we should refill the stores
		if (decreased_store_count)
		{
			err = hip_hchain_stores_refill(esp_prot_transforms[entry->active_transform]);
			if (err < 0)
			{
				HIP_ERROR("error refilling the stores\n");
				goto out_err;
			} else if (err > 0)
			{
				// this means the bex store was updated
				HIP_DEBUG("sending anchor update...\n");
				HIP_IFEL(send_anchor_list_update_to_hipd(entry->active_transform), -1,
						"unable to send anchor list update to hipd\n");
				
				err = 0;
			}
		}
	}
	
  out_err:
    return err;
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
	
	// for now this is the only transform we support
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
int send_anchor_list_update_to_hipd(uint8_t transform)
{
	int err = 0;
	struct hip_common *msg = NULL;
	
	HIP_IFEL(!(msg = create_bexstore_anchors_message(esp_prot_transforms[transform])), -1,
			"failed to create bex store anchors update message\n");
	
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
int send_next_anchor_to_hipd(unsigned char *anchor, uint8_t transform)
{
	int err = 0;
	struct hip_common *msg = NULL;
	
	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "alloc memory for adding sa entry\n");
	
	hip_msg_init(msg);
	
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_IPSEC_NEXT_ANCHOR, 0), -1, 
		 "build hdr failed\n");
	
	HIP_HEXDUMP("anchor: ", anchor, esp_prot_transforms[transform]);
	HIP_IFEL(hip_build_param_contents(msg, (void *)anchor, HIP_PARAM_HCHAIN_ANCHOR,
			esp_prot_transforms[transform]), -1, "build param contents failed\n");
	
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
