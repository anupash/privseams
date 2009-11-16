/**
 * This file contains legacy functions for mobility that should be rewritten for modularity.
 * They are still included in the code base due to locator dependencies with DHT and
 * base exchange code.
 */

#include "hadb_legacy.h"

/**
 * Gets infomation on the given peer IPv6 address.
 *
 * @param entry         corresponding hadb entry of the peer.
 * @param addr          the IPv6 address for which the information is to be
 *                      retrieved.
 * @param lifetime      where the lifetime of @c addr is copied to.
 * @param modified_time where the time when @c addr was added or updated is
 *                      copied to.
 * @return              If @c entry has the address @c addr in its peer address
 *                      list parameters @c spi, @c lifetime, and
 *                      @c modified_time are assigned if they are non-NULL and 1
 *                      is returned, else @c interface_id and @c lifetime are
 *                      not assigned a value and 0 is returned.
 */
int hip_hadb_get_peer_addr_info_old(hip_ha_t *entry, struct in6_addr *addr,
				uint32_t *lifetime, struct timeval *modified_time)
{
	// 99999: REMOVE
        /*struct hip_peer_addr_list_item *peer_addr_list_item;
	int i = 1, ii;
	struct hip_spi_out_item *spi_out;
	hip_list_t *item, *tmp, *a_item, *a_tmp;*/

        struct hip_peer_addr_list_item *peer_addr_list_item;
	int i = 1, ii;
	struct hip_spi_out_item *spi_out;
	hip_list_t *item, *tmp;

        list_for_each_safe(item, tmp, entry->peer_addresses_old, ii)
        {
                peer_addr_list_item = list_entry(item);
         	if (!ipv6_addr_cmp(&peer_addr_list_item->address, addr))
                {
                        _HIP_DEBUG("found\n");
                        if (lifetime)
                                *lifetime = peer_addr_list_item->lifetime;

                        if (modified_time)
                        {
                                modified_time->tv_sec = peer_addr_list_item->modified_time.tv_sec;
                                modified_time->tv_usec = peer_addr_list_item->modified_time.tv_usec;
                        }

                        return 1;
                }

                i++;
        }

	// 99999: REMOVE
        /* assumes already locked entry */
/*	list_for_each_safe(item, tmp, entry->spis_out_old, ii)
	{
		spi_out = list_entry(item);
		list_for_each_safe(a_item, a_tmp, entry->peer_addresses_old, iii)
		{
			s = list_entry(a_item);
			if (!ipv6_addr_cmp(&s->address, addr))
			{
				_HIP_DEBUG("found\n");
				if (lifetime)
					*lifetime = s->lifetime;
				if (modified_time)
				{
					modified_time->tv_sec = s->modified_time.tv_sec;
					modified_time->tv_usec = s->modified_time.tv_usec;
				}
				if (spi)
					*spi = spi_out->spi;
				return 1;
			}
			i++;
		}
	}*/

	_HIP_DEBUG("not found\n");
	return 0;
}

/**
 * Deletes IPv6 address from the entry's list of peer addresses
 *
 * @param entry corresponding hadb entry of the peer
 * @param addr IPv6 address to be deleted
 */
void hip_hadb_delete_peer_addrlist_one_old(hip_ha_t *ha, struct in6_addr *addr)
{
	struct hip_peer_addr_list_item *peer_addr_list_item;
	int i;
	hip_list_t *item, *tmp;

	/* possibly deprecated function .. */

        list_for_each_safe(item, tmp, ha->peer_addresses_old, i)
        {
                peer_addr_list_item = list_entry(item);
                if (!ipv6_addr_cmp(&peer_addr_list_item->address, addr))
                {
                        _HIP_DEBUG("deleting address\n");
                        list_del(item, ha->peer_addresses_old);
                        HIP_FREE(item);
                        /* if address is on more than one spi list then do not goto out */
                        goto out;
                }
            }

 out:
	return;
}

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

/* add an address belonging to the SPI list */
/* or update old values */

// 99999 REMOVE!
/*int hip_hadb_add_addr_to_spi_old(hip_ha_t *entry, uint32_t spi,
			     struct in6_addr *addr,
			     int is_bex_address, uint32_t lifetime,
			     int is_preferred_addr)*/
int hip_hadb_add_addr_old(hip_ha_t *entry, struct in6_addr *addr,
			     int is_bex_address, uint32_t lifetime,
			     int is_preferred_addr)
{
	return  hip_hadb_add_udp_addr_old(entry, addr, is_bex_address,
			lifetime, is_preferred_addr, 0, HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI_PRIORITY,0);
	//remove by santtu
#if 0
	int err = 0, new = 1, i;
	struct hip_spi_out_item *spi_list;
	struct hip_peer_addr_list_item *new_addr = NULL;
	struct hip_peer_addr_list_item *a;
	hip_list_t *item, *tmp;
	struct in6_addr *preferred_address;
	/* Assumes already locked entry */
	HIP_DEBUG("spi=0x%x is_preferred_addr=%d\n", spi, is_preferred_addr);

	spi_list = hip_hadb_get_spi_list(entry, spi);
	if (!spi_list)
	{
		HIP_ERROR("SPI list for 0x%x not found\n", spi);
		err = -EEXIST;
		goto out_err;
	}

	/* Check if addr already exists. If yes, then just update values. */
	list_for_each_safe(item, tmp, spi_list->peer_addr_list, i)
	{
		a = list_entry(item);
		if (!ipv6_addr_cmp(&a->address, addr))
		{
			// Do we send a verification if state is unverified?
			// The address should be awaiting verifivation already
			new_addr = a;
			new = 0;
			break;
		}
	}

	if (new)
	{
		HIP_DEBUG("create new addr item to SPI list\n");
		/* SPI list does not contain the address, add the address to the SPI list */
		new_addr = (struct hip_peer_addr_list_item *)HIP_MALLOC(sizeof(struct hip_peer_addr_list_item), 0);
		if (!new_addr)
		{
			HIP_ERROR("item HIP_MALLOC failed\n");
			err = -ENOMEM;
			goto out_err;
		}
	}
	else HIP_DEBUG("update old addr item\n");

	new_addr->lifetime = lifetime;
	if (new) ipv6_addr_copy(&new_addr->address, addr);

	/* If the address is already bound, its lifetime is updated.
	   If the status of the address is DEPRECATED, the status is
	   changed to UNVERIFIED.  If the address is not already bound,
	   the address is added, and its status is set to UNVERIFIED. */


	/* We switch off the part that make no answer with echo response message
	   to the initiator. The reason is that we need the whole update schema work
	   for the program to run corrctly. This purely optimization part can be changed
	   latter. - Andrey.
	*/
#if 0
	if (!new)
	{
		switch (new_addr->address_state)
		{
		case PEER_ADDR_STATE_DEPRECATED:
			new_addr->address_state = PEER_ADDR_STATE_UNVERIFIED;
			HIP_DEBUG("updated address state DEPRECATED->UNVERIFIED\n");
			break;
 		case PEER_ADDR_STATE_ACTIVE:
			HIP_DEBUG("address state stays in ACTIVE\n");
			break;
		default:
			// Does this mean that unverified cant be here? Why?
			HIP_ERROR("state is UNVERIFIED, shouldn't even be here ?\n");
			break;
		}
	}
	else
	{
#endif
             if (is_bex_address)
		{
			/* workaround for special case */
 			HIP_DEBUG("address is base exchange address, setting state to ACTIVE\n");
			new_addr->address_state = PEER_ADDR_STATE_ACTIVE;
			HIP_DEBUG("setting bex addr as preferred address\n");
			ipv6_addr_copy(&entry->peer_addr, addr);
			new_addr->seq_update_id = 0;
		} else {
			HIP_DEBUG("address's state is set in state UNVERIFIED\n");
			new_addr->address_state = PEER_ADDR_STATE_UNVERIFIED;
			err = entry->hadb_update_func->hip_update_send_echo(entry, spi, new_addr);

			/** @todo: check! If not acctually a problem (during Handover). Andrey. */
			if( err==-ECOMM ) err = 0;
		}
		//}

	do_gettimeofday(&new_addr->modified_time);
	new_addr->is_preferred = is_preferred_addr;
	if(is_preferred_addr){
            //HIP_DEBUG("Since the address is preferred, we set the entry preferred_address as such\n");
              ipv6_addr_copy(&entry->peer_addr, &new_addr->address);
	}
	if (new) {
		HIP_DEBUG("adding new addr to SPI list\n");
		list_add(new_addr, spi_list->peer_addr_list);
	}

 out_err:
	HIP_DEBUG("returning, err=%d\n", err);
	return err;
#endif
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

//add by santtu
/* add an address belonging to the SPI list */
/* or update old values */
/* 99999 REMOVE!
int hip_hadb_add_udp_addr_to_spi(hip_ha_t *entry, uint32_t spi,
			     struct in6_addr *addr,
			     int is_bex_address, uint32_t lifetime,
			     int is_preferred_addr,
			     uint16_t port,
			     uint32_t priority,
			     uint8_t kind)*/
int hip_hadb_add_udp_addr_old(hip_ha_t *ha, struct in6_addr *addr,
			     int is_bex_address, uint32_t lifetime,
			     int is_preferred_addr,
			     uint16_t port,
			     uint32_t priority,
			     uint8_t kind)
{
	int err = 0, new = 1, i;
	struct hip_peer_addr_list_item *new_addr = NULL;
	struct hip_peer_addr_list_item *a;
	hip_list_t *item, *tmp;
	struct in6_addr *preferred_address;

        HIP_DEBUG("is_preferred_addr=%d\n", is_preferred_addr);

	/* Check if addr already exists. If yes, then just update values. */
	list_for_each_safe(item, tmp, ha->peer_addresses_old, i)
	{
		a = list_entry(item);
		if ((!ipv6_addr_cmp(&a->address, addr) )&& a->port == port)
		{
			// Do we send a verification if state is unverified?
			// The address should be awaiting verifivation already
			HIP_DEBUG_HIT("found address: ",&a->address);
			HIP_DEBUG("found port: %d\n",a->port );

			new_addr = a;
			new = 0;
			break;
		}
	}

	if (new)
	{
		HIP_DEBUG("create new addr item to SPI list\n");
		/* SPI list does not contain the address, add the address to the SPI list */
		new_addr = (struct hip_peer_addr_list_item *)HIP_MALLOC(sizeof(struct hip_peer_addr_list_item), 0);
		if (!new_addr)
		{
			HIP_ERROR("item HIP_MALLOC failed\n");
			err = -ENOMEM;
			goto out_err;
		}
	}
	else HIP_DEBUG("update old addr item\n");

	new_addr->lifetime = lifetime;
	if (new) {
		ipv6_addr_copy(&new_addr->address, addr);
//add by santtu
		new_addr->port = port;
		new_addr->priority = priority;
		new_addr->kind = kind;
//end add
	}

	/* If the address is already bound, its lifetime is updated.
	   If the status of the address is DEPRECATED, the status is
	   changed to UNVERIFIED.  If the address is not already bound,
	   the address is added, and its status is set to UNVERIFIED. */


	/* We switch off the part that make no answer with echo response message
	   to the initiator. The reason is that we need the whole update schema work
	   for the program to run corrctly. This purely optimization part can be changed
	   latter. - Andrey.
	*/

	if (is_bex_address)
	{
		/* workaround for special case */
		HIP_DEBUG("address is base exchange address, setting state to ACTIVE\n");
		new_addr->address_state = PEER_ADDR_STATE_ACTIVE;
		HIP_DEBUG("setting bex addr as preferred address\n");
		ipv6_addr_copy(&ha->peer_addr, addr);
		new_addr->seq_update_id = 0;
	} else {
		HIP_DEBUG("address's state is set in state UNVERIFIED\n");
		new_addr->address_state = PEER_ADDR_STATE_UNVERIFIED;
//modify by santtu
		if(hip_get_nat_mode(ha) == HIP_NAT_MODE_PLAIN_UDP && hip_relay_get_status() != HIP_RELAY_ON){
			
			err = hip_update_send_echo_old(ha, ha->spi_outbound_current, new_addr);
			
			/** @todo: check! If not acctually a problem (during Handover). Andrey. */
			if( err==-ECOMM ) err = 0;
		}
//end modify
	}
	//}

	do_gettimeofday(&new_addr->modified_time);
	new_addr->is_preferred = is_preferred_addr;
	if(is_preferred_addr){
		//HIP_DEBUG("Since the address is preferred, we set the entry preferred_address as such\n");
		ipv6_addr_copy(&ha->peer_addr, &new_addr->address);
		ha->peer_udp_port = new_addr->port;
	}
	if (new) {
		HIP_DEBUG("adding new addr to SPI list\n");
		list_add(new_addr, ha->peer_addresses_old);
		
		HIP_DEBUG("new peer list item address: %d ",new_addr);
	}

 out_err:
	HIP_DEBUG("returning, err=%d\n", err);
	return err;
}
