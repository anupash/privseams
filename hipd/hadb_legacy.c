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
		if(hip_nat_get_control(ha) != HIP_NAT_MODE_ICE_UDP && hip_relay_get_status() != HIP_RELAY_ON){
			
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
