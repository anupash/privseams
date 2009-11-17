// 17.11.2009:
// THIS FILE IS OBSOLETED.
// PLEASE DO NOT USE!

#if 0
/* assume already locked entry */
// SYNCH
int hip_hadb_add_outbound_spi_old(hip_ha_t *entry, struct hip_spi_out_item *data)
{
	int err = 0, i;
	struct hip_spi_out_item *spi_item;
	uint32_t spi_out;
	hip_list_t *item, *tmp;

	/* assumes locked entry ? */
	spi_out = data->spi;

	_HIP_DEBUG("SPI_out=0x%x\n", spi_out);
	list_for_each_safe(item, tmp, entry->spis_out_old, i)
	{
		spi_item = list_entry(item);
		if (spi_item->spi == spi_out)
		{
			HIP_DEBUG("not adding duplicate SPI 0x%x\n", spi_out);
			goto out;
		}
	}

	spi_item = (struct hip_spi_out_item *)HIP_MALLOC(sizeof(struct hip_spi_out_item), GFP_ATOMIC);
	if (!spi_item)
	{
		HIP_ERROR("item HIP_MALLOC failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	memcpy(spi_item, data, sizeof(struct hip_spi_out_item));
// 	INIT_LIST_HEAD(&spi_item->peer_addr_list);
	spi_item->peer_addr_list = hip_ht_init(hip_hash_peer_addr, hip_match_peer_addr);
	ipv6_addr_copy(&spi_item->preferred_address, &in6addr_any);
	list_add(spi_item, entry->spis_out_old);
	HIP_DEBUG("added SPI 0x%x to the outbound SPI list\n", spi_out);

 out_err:
 out:
	return err;
}

/* assume already locked entry */
int hip_hadb_add_spi_old(hip_ha_t *entry, int direction, void *data)
{
	int err = -EINVAL;

	if (direction == HIP_SPI_DIRECTION_IN)
		err = hip_hadb_add_inbound_spi_old(entry, (struct hip_spi_in_item *) data);
	else if (direction == HIP_SPI_DIRECTION_OUT)
		err = hip_hadb_add_outbound_spi_old(entry, (struct hip_spi_out_item *) data);
	else
		HIP_ERROR("bug, invalid direction %d\n", direction);

	return err;
}

/* Get the SPI of given ifindex, returns 0 if ifindex was not found  */
uint32_t hip_hadb_get_spi_old(hip_ha_t *entry, int ifindex)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	HIP_DEBUG("ifindex=%d\n", ifindex);
	list_for_each_safe(item, tmp, entry->spis_in_old, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x\n", spi_item->ifindex, spi_item->spi);
		if (spi_item->ifindex == ifindex || ifindex == -1)
		{
			HIP_DEBUG("found SPI 0x%x\n", spi_item->spi);
			return spi_item->spi;
		}
	}

	HIP_DEBUG("SPI not found for the ifindex\n");
	return 0;
}

/* spi_out is the SPI which was in the received NES Old SPI field */
void hip_update_set_new_spi_in_old(hip_ha_t *entry, uint32_t spi, uint32_t new_spi,
			       uint32_t spi_out /* test */)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	_HIP_DEBUG("spi=0x%x new_spi=0x%x spi_out=0x%x\n", spi, new_spi, spi_out);

	list_for_each_safe(item, tmp, entry->spis_in_old, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: spi=0x%x new_spi=0x%x\n",
				spi_item->spi, spi_item->new_spi);
		if (spi_item->spi == spi)
		{
			HIP_DEBUG("setting new_spi\n");
			if (!spi_item->updating)
			{
				_HIP_ERROR("SA update not in progress, continuing anyway\n");
			}
			if ((spi_item->spi != spi_item->new_spi) && spi_item->new_spi)
			{
				HIP_ERROR("warning: previous new_spi is not zero: 0x%x\n",
						spi_item->new_spi);
			}
			spi_item->new_spi = new_spi;
			spi_item->esp_info_spi_out = spi_out; /* maybe useless */
			break;
		}
	}
}

/* have_esp_info is 1, if there is ESP_INFO in the same packet as the ACK was */
void hip_update_handle_ack_old(hip_ha_t *entry, struct hip_ack *ack, int have_esp_info)
{
	size_t n = 0, i = 0;
	uint32_t *peer_update_id = NULL;

	HIP_DEBUG("hip_update_handle_ack() invoked with have_esp_info = %d.\n",
		  have_esp_info);

	if (ack == NULL) {
		HIP_ERROR("Function parameter ack was NULL in "\
			  "hip_update_handle_ack().\n");
		goto out_err;
	}

	if (hip_get_param_contents_len(ack) % sizeof(uint32_t)) {
		HIP_ERROR("ACK parameter length is not divisible by 4 (%u).\n",
			  hip_get_param_contents_len(ack));
		goto out_err;
	}

	n = hip_get_param_contents_len(ack) / sizeof(uint32_t);

	HIP_DEBUG("Number of peer Update IDs in ACK parameter: %d.\n", n);

	peer_update_id =
		(uint32_t *) ((void *)ack + sizeof(struct hip_tlv_common));

	/* Loop through all peer Update IDs in the ACK parameter. */
	for (i = 0; i < n; i++, peer_update_id++) {
		hip_list_t *item, *tmp;
		struct hip_spi_in_item *in_item;
		uint32_t puid = ntohl(*peer_update_id);
		int i;

		_HIP_DEBUG("peer Update ID=%u\n", puid);

		/* See if your ESP_INFO is acked and maybe if corresponging
		   ESP_INFO was received */
		list_for_each_safe(item, tmp, entry->spis_in_old, i) {
			in_item = list_entry(item);
			_HIP_DEBUG("test item: spi_in=0x%x seq=%u\n",
				   in_item->spi, in_item->seq_update_id);
			if (in_item->seq_update_id == puid) {
				_HIP_DEBUG("SEQ and ACK match\n");
				/* Received ACK */
				in_item->update_state_flags |= 0x1;
				/* Received also ESP_INFO */
				if (have_esp_info) {
					in_item->update_state_flags |= 0x2;
				}
			}
		}

	}
 out_err:
	return;
}

/* todo: use jiffies instead of timestamp */
uint32_t hip_hadb_get_latest_inbound_spi_old(hip_ha_t *entry)
{
	hip_list_t *item, *tmp;
	struct hip_spi_in_item *spi_item;
	uint32_t spi = 0;
	unsigned int now = jiffies;
	unsigned long t = ULONG_MAX;
	int i;

	/* assumes already locked entry */

	list_for_each_safe(item, tmp, entry->spis_in_old, i)
	{
		spi_item = list_entry(item);
		HIP_DEBUG("spi_in in loop is 0x%x\n", spi_item->spi);
		if (now - spi_item->timestamp < t)
		{
			spi = spi_item->spi;
			t = now - spi_item->timestamp;
		}
	}

	_HIP_DEBUG("newest spi_in is 0x%x\n", spi);
	return spi;
}

//add by santtu
/* todo: use jiffies instead of timestamp */
uint32_t hip_hadb_get_outbound_spi_old(hip_ha_t *entry)
{
	hip_list_t *item, *tmp;
	struct hip_spi_out_item *spi_item;
	uint32_t spi = 0;
	unsigned int now = jiffies;
	unsigned long t = ULONG_MAX;
	int i;

	/* assumes already locked entry */

	list_for_each_safe(item, tmp, entry->spis_out_old, i)
	{
		spi_item = list_entry(item);

		spi = spi_item->spi;

		break;

	}

	_HIP_DEBUG("newest spi_in out 0x%x\n", spi);
	return spi;
}

//end add
/* get pointer to the outbound SPI list or NULL if the outbound SPI
   list does not exist */
struct hip_spi_out_item *hip_hadb_get_spi_list_old(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_out_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	/* assumes already locked entry */

	_HIP_DEBUG("Search spi list for SPI=0x%x\n", spi);
	list_for_each_safe(item, tmp, entry->spis_out_old, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("search: 0x%x ?= 0x%x\n", spi_item->spi, spi);
		if (spi_item->spi == spi) return spi_item;
	}

	return NULL;
}

/* get pointer to the inbound SPI list or NULL if SPI list does not exist */
struct hip_spi_in_item *hip_hadb_get_spi_in_list_old(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	/* assumes already locked entry */

	HIP_DEBUG("SPI=0x%x\n", spi);
	list_for_each_safe(item, tmp, entry->spis_in_old, i)
	{
		spi_item = list_entry(item);
		if (spi_item->spi == spi) return spi_item;
	}

	return NULL;
}

void hip_hadb_dump_spis_in_old(hip_ha_t *entry)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	HIP_DEBUG("start\n");
	HIP_LOCK_HA(entry);
	list_for_each_safe(item, tmp, entry->spis_in_old, i)
	{
		spi_item = list_entry(item);
		HIP_DEBUG(" SPI=0x%x new_SPI=0x%x esp_info_SPI_out=0x%x ifindex=%d "
			  "ts=%lu updating=%d keymat_index=%u upd_flags=0x%x seq_update_id=%u ESP_INFO=old 0x%x,new 0x%x,km %u\n",
			  spi_item->spi, spi_item->new_spi, spi_item->esp_info_spi_out, spi_item->ifindex,
			  jiffies - spi_item->timestamp, spi_item->updating, spi_item->keymat_index,
			  spi_item->update_state_flags, spi_item->seq_update_id,
			  spi_item->stored_received_esp_info.old_spi,
			  spi_item->stored_received_esp_info.old_spi,
			  spi_item->stored_received_esp_info.keymat_index);
	}
	HIP_UNLOCK_HA(entry);
	HIP_DEBUG("end\n");
}

void hip_hadb_dump_spis_out_old(hip_ha_t *entry)
{
	struct hip_spi_out_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	HIP_DEBUG("start\n");
	HIP_LOCK_HA(entry);
	list_for_each_safe(item, tmp, entry->spis_out_old, i)
	{
		spi_item = list_entry(item);
		HIP_DEBUG(" SPI=0x%x new_SPI=0x%x seq_update_id=%u\n",
			  spi_item->spi, spi_item->new_spi, spi_item->seq_update_id);
	}
	HIP_UNLOCK_HA(entry);
	HIP_DEBUG("end\n");
}

#endif
