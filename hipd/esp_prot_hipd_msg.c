#include "esp_prot_hipd_msg.h"
#include "esp_prot_anchordb.h"
#include "esp_prot_common.h"

/** 
 * activates the esp protection extension in the hipd
 * 
 * NOTE: this is called by the hipd when receiving the respective message
 * from the firewall
 **/
int hip_esp_protection_extension_transform(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	int err = 0;
	uint8_t transform = 0;
	extern uint8_t hip_esp_prot_ext_transform;
	
	// process message and store anchor elements in the db
	param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_UINT);
	transform = *((uint8_t *)hip_get_param_contents_direct(param));
	HIP_DEBUG("esp protection extension transform: %u \n", transform);
	
	// right now we only support the default transform
	if (transform > ESP_PROT_TRANSFORM_UNUSED)
	{
		hip_esp_prot_ext_transform = transform;
		
		HIP_DEBUG("switched to esp protection extension\n");
	}
	else
	{
		// error or esp protection extension switched off
		hip_esp_prot_ext_transform = ESP_PROT_TRANSFORM_UNUSED;
		
		HIP_DEBUG("switched to normal esp mode\n");
	}
	
	/* we have to make sure that the precalculated R1s include the esp
	 * protection extension transform */
	HIP_DEBUG("recreate all R1s\n");
	HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1, "failed to recreate all R1s\n");
	
  out_err:
  	return err;
}

int add_esp_prot_transform_to_r1(hip_common_t *msg)
{
	extern uint8_t hip_esp_prot_ext_transform;
	int err = 0;
	
	/* only supported in usermode and optional there
 	 * 
 	 * add the transform only when usermode is active */
 	if (hip_use_userspace_ipsec)
 	{
 		HIP_DEBUG("userspace IPsec hint: esp protection extension might be in use\n");
 		
 		if (hip_esp_prot_ext_transform > ESP_PROT_TRANSFORM_UNUSED)
 		{
	 		/* the extension is switched on */
 			HIP_IFEL(hip_build_param_esp_prot_transform(msg, hip_esp_prot_ext_transform),
 					-1, "Building of ESP protection mode failed\n");
 			
 		} else
 		{	
 			HIP_DEBUG("esp protection extension not active\n");
 			HIP_IFEL(hip_build_param_esp_prot_transform(msg, ESP_PROT_TRANSFORM_UNUSED),
 					-1, "Building of ESP protection mode failed\n");
 		}
 	} else
 	{
 		HIP_DEBUG("userspace IPsec hint: esp protection extension UNUSED, skip\n");
 	}
 	
 	_HIP_DUMP_MSG(msg);
 	
  out_err:
 	return err;
}

int add_esp_prot_transform_to_I2(hip_common_t *i2, hip_ha_t *entry, struct hip_context *ctx)
{
	struct hip_param *param = NULL;
	struct esp_prot_transform *prot_transform = NULL;
	uint8_t transform = 0;
	extern uint8_t hip_esp_prot_ext_transform;
	int err = 0;
	
	/* this is only handled if we are using userspace ipsec,
	 * otherwise we just ignore it */
	if (hip_use_userspace_ipsec)
	{
		HIP_DEBUG("userspace IPsec hint: ESP extension might be in use\n");
		param = hip_get_param(ctx->input, HIP_PARAM_ESP_PROT_TRANSFORM);
		
		// check if the transform parameter was sent
		if (param)
		{
			prot_transform = (struct esp_prot_transform *) param;
			transform = prot_transform->transform;
			
			HIP_DEBUG("R1 contains ESP protection transform: %u\n", transform);
			
			// check if we are using the extension
			if (hip_esp_prot_ext_transform > ESP_PROT_TRANSFORM_UNUSED)
			{
				// check if the transforms match
				if (hip_esp_prot_ext_transform == transform)
				{
					HIP_DEBUG("matching ESP extension transform: %u\n",
							hip_esp_prot_ext_transform);
					HIP_DEBUG("setting and sending transform...\n");
					
					// set transform for this connection and advertise
					entry->esp_prot_transform = transform;
					HIP_IFEL(hip_build_param_esp_prot_transform(i2, transform),
							-1, "Building of ESP protection mode failed\n");
				} else
				{
					HIP_DEBUG("different local ESP extension transform: %u\n",
							hip_esp_prot_ext_transform);
					HIP_DEBUG("setting and sending transform UNUSED...\n");
					
					// set to unused and reply with according parameter
					entry->esp_prot_transform = ESP_PROT_TRANSFORM_UNUSED;
					HIP_IFEL(hip_build_param_esp_prot_transform(i2, ESP_PROT_TRANSFORM_UNUSED),
							-1, "Building of ESP protection mode failed\n");
				}
			} else
			{
				HIP_DEBUG("ESP extension switched off locally, setting and sending UNUSED transform...\n");
				
				entry->esp_prot_transform = ESP_PROT_TRANSFORM_UNUSED;
				// advertise that we are not using the extension
				HIP_IFEL(hip_build_param_esp_prot_transform(i2, ESP_PROT_TRANSFORM_UNUSED),
						-1, "Building of ESP protection mode failed\n");
			}
		} else if (!param)
		{
			HIP_DEBUG("R1 does not contain ESP protection transform, setting UNUSED\n");
			
			// if the other end-host does not want to use the extension, we don't either
			entry->esp_prot_transform = ESP_PROT_TRANSFORM_UNUSED;
		}
	} else
	{
		HIP_DEBUG("no userspace IPsec hint for ESP extension, setting UNUSED\n");
		
		// make sure we don't add the anchor now and don't add any transform or anchor
		entry->esp_prot_transform = ESP_PROT_TRANSFORM_UNUSED;
	}

  out_err:
 	return err;
}

int add_esp_prot_anchor_to_I2(hip_common_t *i2, hip_ha_t *entry)
{
	unsigned char *anchor = NULL;
	int err = 0;
	
	// only add, if extension in use and we agreed on a transform
	if (entry->esp_prot_transform)
	{
		if (has_more_anchors())
		{
			HIP_IFEL(!(anchor = get_next_anchor()), -1,
					"no anchor elements available, threading?\n");
			HIP_IFEL(hip_build_param_esp_prot_anchor(i2, anchor,
					esp_prot_transforms[entry->esp_prot_transform]), -1,
					"Building of ESP protection anchor failed\n");
			HIP_HEXDUMP("added anchor: ", anchor,
					esp_prot_transforms[entry->esp_prot_transform]);
			
			// store local_anchor
			entry->esp_local_anchor = anchor;
		} else
		{
			// fall back
			HIP_ERROR("we agreed on using esp hchain protection, but no elements");
			entry->esp_prot_transform = ESP_PROT_TRANSFORM_UNUSED;
		}
	}

  out_err:
 	return err;
}

int handle_esp_prot_transform_in_I2(hip_ha_t *entry, struct hip_context *ctx)
{
	struct hip_param *param = NULL;
	struct esp_prot_transform *prot_transform = NULL;
	uint8_t transform = 0;
	extern uint8_t hip_esp_prot_ext_transform;
	int err = 0;
	
	/* only supported in usermode and optional there
 	 * 
 	 * process the transform only when usermode is active */
 	HIP_DEBUG("hip_use_userspace_ipsec is %i\n", hip_use_userspace_ipsec);
 	if (hip_use_userspace_ipsec)
 	{
 		HIP_DEBUG("userspace IPsec hint: esp protection extension might be in use\n");
 		
 		if (hip_esp_prot_ext_transform > ESP_PROT_TRANSFORM_UNUSED)
 		{
 			param = hip_get_param(ctx->input, HIP_PARAM_ESP_PROT_TRANSFORM);
			/* process this if the other end-host supports the extension
			 * (parameter incl in R1) */
			if (param)
			{
				prot_transform = (struct esp_prot_transform *) param;
				transform = prot_transform->transform;
				
				// TODO agree on transform
				// right now we only support 2 transform, so we can just copy
				entry->esp_prot_transform = transform;
				
				HIP_DEBUG("esp protection transform in I2: %u \n", transform);
			} else
			{
				HIP_DEBUG("esp protection extension active, but not used by peer host -> setting UNUSED\n");
				entry->esp_prot_transform = ESP_PROT_TRANSFORM_UNUSED;
			}
 		} else
 		{	
 			HIP_DEBUG("esp protection extension not active, setting UNUSED\n");
 			entry->esp_prot_transform = ESP_PROT_TRANSFORM_UNUSED;
 		}
 	} else
 	{
 		HIP_DEBUG("userspace IPsec hint: esp protection extension UNUSED, skipped\n");
 		entry->esp_prot_transform = ESP_PROT_TRANSFORM_UNUSED;
 	}
 	
  out_err:
 	return err;
}

int handle_esp_prot_anchor_in_I2(hip_ha_t *entry, struct hip_context *ctx)
{
	struct hip_param *param = NULL;
	struct esp_prot_anchor *prot_anchor = NULL;
	unsigned char *anchor = NULL;
	int err = 0;
	
	/* only process the anchor parameter, if we are going to use it */
	if (entry->esp_prot_transform)
	{
		if (param = hip_get_param(ctx->input, HIP_PARAM_ESP_PROT_ANCHOR))
		{
			prot_anchor = (struct esp_prot_anchor *) param;
			
			// distinguish different hash lengths/transforms
			if (entry->esp_prot_transform > ESP_PROT_TRANSFORM_UNUSED)
			{
				anchor = (unsigned char *)
						malloc(esp_prot_transforms[entry->esp_prot_transform]);
				
				memcpy(anchor, prot_anchor->anchor,
						esp_prot_transforms[entry->esp_prot_transform]);
				
				HIP_HEXDUMP("received anchor: ", anchor,
						esp_prot_transforms[entry->esp_prot_transform]);
			} else
			{
				HIP_ERROR("received anchor with unknown transform, falling back\n");
				
				entry->esp_prot_transform = ESP_PROT_TRANSFORM_UNUSED;
			}
			
			// store peer_anchor
			entry->esp_peer_anchor = anchor;
		} else
		{
			// fall back option
			HIP_DEBUG("agreed on using esp hchain extension, but no anchor sent or error\n");
			
			entry->esp_prot_transform = ESP_PROT_TRANSFORM_UNUSED;
		}
	}
	
  out_err:
 	return err;
}

int add_esp_prot_anchor_to_R2(hip_common_t *r2, hip_ha_t *entry)
{
	unsigned char *anchor = NULL;
	int err = 0;
	
	// only add, if extension in use, we agreed on a transform and no error until now
	if (entry->esp_prot_transform)
	{
		if (has_more_anchors())
		{
			HIP_IFEL(!(anchor = get_next_anchor()), -1,
					"no anchor elements available, threading?\n");
			HIP_IFEL(hip_build_param_esp_prot_anchor(r2, anchor,
					esp_prot_transforms[entry->esp_prot_transform]), -1,
					"Building of ESP protection anchor failed\n");
			HIP_HEXDUMP("added anchor: ", anchor,
					esp_prot_transforms[entry->esp_prot_transform]);
			
			// store local_anchor
			entry->esp_local_anchor = anchor;
		} else
		{
			// fall back
			HIP_ERROR("we agreed on using esp hchain protection, but no elements");
			entry->esp_prot_transform = ESP_PROT_TRANSFORM_UNUSED;
		}
	}
	
  out_err:
 	return err;
}

int handle_esp_prot_anchor_in_R2(hip_ha_t *entry, struct hip_context *ctx)
{
	struct hip_param *param = NULL;
	struct esp_prot_anchor *prot_anchor = NULL;
	unsigned char *anchor = NULL;
	int err = 0;
	
	param = hip_get_param(ctx->input, HIP_PARAM_ESP_PROT_ANCHOR);
	// only process anchor, if we agreed on using it before
	if (entry->esp_prot_transform && param)
	{
		prot_anchor = (struct esp_prot_anchor *) param;
		
		anchor = (unsigned char *)malloc(esp_prot_transforms[entry->esp_prot_transform]);
		memcpy(anchor, prot_anchor->anchor,
				esp_prot_transforms[entry->esp_prot_transform]);
		
		HIP_HEXDUMP("received anchor: ", anchor,
				esp_prot_transforms[entry->esp_prot_transform]);
		
		// store peer_anchor
		entry->esp_peer_anchor = anchor;
	} else
	{
		HIP_DEBUG("agreed on using esp hchain extension, but no anchor sent or error\n");
		// fall back option
		entry->esp_prot_transform = ESP_PROT_TRANSFORM_UNUSED;
	}
	
  out_err:
 	return err;
}
