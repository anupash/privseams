/* Set the ifindex of given SPI */
/* assumes locked HA */
void hip_hadb_set_spi_ifindex_deprecated(hip_ha_t *entry,
                                         uint32_t spi,
                                         int ifindex)
{
    struct hip_spi_in_item *spi_item;
    hip_list_t *item, *tmp;
    int i;

    /* assumes that inbound spi already exists in ha's spis_in_old */
    HIP_DEBUG("SPI=0x%x ifindex=%d\n", spi, ifindex);
    list_for_each_safe(item, tmp, entry->spis_in_old, i)
    {
        spi_item = list_entry(item);
        _HIP_DEBUG("test item: ifindex=%d spi=0x%x\n",
                   spi_item->ifindex, spi_item->spi);
        if (spi_item->spi == spi) {
            HIP_DEBUG("found updated spi-ifindex mapping\n");
            spi_item->ifindex = ifindex;
            return;
        }
    }
    HIP_DEBUG("SPI not found, returning\n");
}

/* Get the ifindex of given SPI, returns 0 if SPI was not found */
int hip_hadb_get_spi_ifindex_deprecated(hip_ha_t *entry, uint32_t spi)
{
    struct hip_spi_in_item *spi_item;
    hip_list_t *item, *tmp;
    int i;

    _HIP_DEBUG("spi=0x%x\n", spi);
    list_for_each_safe(item, tmp, entry->spis_in_old, i)
    {
        spi_item = list_entry(item);
        _HIP_DEBUG("test item: ifindex=%d spi=0x%x\n",
                   spi_item->ifindex, spi_item->spi);
        if (spi_item->spi == spi || spi_item->new_spi == spi) {
            _HIP_DEBUG("found\n");
            return spi_item->ifindex;
        }
    }
    HIP_DEBUG("ifindex not found for the SPI 0x%x\n", spi);
    return 0;
}

uint32_t hip_update_get_prev_spi_in_deprecated_rekeying(hip_ha_t *entry,
                                                        uint32_t peer_update_id)
{
    struct hip_spi_in_item *spi_item;
    hip_list_t *item, *tmp;
    int i;

    HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
    list_for_each_safe(item, tmp, entry->spis_in_old, i)
    {
        spi_item = list_entry(item);
        _HIP_DEBUG("test item: ifindex=%d spi=0x%x nes_spi_out=0x%x seq_id=%u\n",
                   spi_item->ifindex, spi_item->spi, spi_item->nes_spi_out,
                   spi_item->seq_update_id);
        if (spi_item->seq_update_id == peer_update_id) {
            HIP_DEBUG("found SPI 0x%x\n", spi_item->spi);
            return spi_item->spi;
        }
    }
    HIP_DEBUG("SPI not found\n");
    return 0;
}

/* Get the SPI of the SA belonging to the interface through
 * which we received the UPDATE */
/* also sets updating flag of SPI to 1 */
uint32_t hip_get_spi_to_update_in_established_deprecated(hip_ha_t *entry,
                                                         struct in6_addr *dev_addr)
{
    struct hip_spi_in_item *spi_item;
    hip_list_t *item, *tmp;
    int i;
    int ifindex;

    HIP_DEBUG_HIT("dst dev_addr", dev_addr);
    ifindex = hip_devaddr2ifindex(dev_addr);
    HIP_DEBUG("ifindex of dst dev=%d\n", ifindex);
    if (!ifindex) {
        return 0;
    }

    list_for_each_safe(item, tmp, entry->spis_in_old, i)
    {
        spi_item = list_entry(item);
        _HIP_DEBUG("test item: ifindex=%d spi=0x%x\n",
                   spi_item->ifindex, spi_item->spi);
        if (spi_item->ifindex == ifindex) {
            spi_item->updating = 1;
            return spi_item->spi;
        }
    }

    HIP_DEBUG("SPI not found for ifindex\n");
    return 0;
}

void hip_set_spi_update_status_deprecated_rekeying(hip_ha_t *entry,
                                                   uint32_t spi, int set)
{
    struct hip_spi_in_item *spi_item;
    hip_list_t *item, *tmp;
    int i;

    HIP_DEBUG("spi=0x%x set=%d\n", spi, set);
    list_for_each_safe(item, tmp, entry->spis_in_old, i)
    {
        spi_item = list_entry(item);
        _HIP_DEBUG("test item: ifindex=%d spi=0x%x updating=%d\n",
                   spi_item->ifindex, spi_item->spi, spi_item->updating);
        if (spi_item->spi == spi) {
            HIP_DEBUG("setting updating status to %d\n", set);
            spi_item->updating = set;
            break;
        }
    }
}

/* just sets the new_spi field */
void hip_update_set_new_spi_out_deprecated_rekeying(hip_ha_t *entry,
                                                    uint32_t spi,
                                                    uint32_t new_spi)
{
    struct hip_spi_in_item *spi_item;
    hip_list_t *item, *tmp;
    int i;

    _HIP_DEBUG("spi=0x%x new_spi=0x%x\n", spi, new_spi);
    list_for_each_safe(item, tmp, entry->spis_in_old, i)
    {
        spi_item = list_entry(item);
        _HIP_DEBUG("test item: spi=0x%x new_spi=0x%x\n",
                   spi_item->spi, spi_item->new_spi);
        if (spi_item->spi == spi) {
            _HIP_DEBUG("setting new_spi\n");
            if (spi_item->new_spi) {
                HIP_ERROR("previous new_spi is not zero: 0x%x\n",
                          spi_item->new_spi);
                HIP_ERROR("todo: delete previous new_spi\n");
            }
            spi_item->new_spi = new_spi;
            break;
        }
    }
}

uint32_t hip_update_get_new_spi_in_deprecated_rekeying(hip_ha_t *entry,
                                                       uint32_t peer_update_id)
{
    struct hip_spi_in_item *spi_item;
    hip_list_t *item, *tmp;
    int i;

    _HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
    list_for_each_safe(item, tmp, entry->spis_in_old, i)
    {
        spi_item = list_entry(item);
        _HIP_DEBUG("test item: spi=0x%x new_spi=0x%x\n",
                   spi_item->spi, spi_item->new_spi);
        if (spi_item->seq_update_id == peer_update_id) {
            if (spi_item->new_spi) {
                return spi_item->new_spi;
            }
            return spi_item->spi;
        }
    }
    HIP_DEBUG("New SPI not found\n");
    return 0;
}

/* switch from Old SPI to New SPI (inbound SA) */
/* caller must delete the Old SPI */
void hip_update_switch_spi_in_deprecated_rekeying(hip_ha_t *entry,
                                                  uint32_t old_spi)
{
    struct hip_spi_in_item *spi_item;
    hip_list_t *item, *tmp;
    int i;

    _HIP_DEBUG("old_spi=0x%x\n", old_spi);
    list_for_each_safe(item, tmp, entry->spis_in_old, i)
    {
        spi_item = list_entry(item);
        _HIP_DEBUG("test item: ifindex=%d spi=0x%x new_spi=0x%x nes_spi_out=0x%x seq_id=%u\n",
                   spi_item->ifindex, item->spi, spi_item->new_spi,
                   spi_item->nes_spi_out, spi_item->seq_update_id);
        if (spi_item->spi == old_spi) {
            _HIP_DEBUG("switching\n");
            spi_item->spi              = spi_item->new_spi;
            spi_item->new_spi          = 0;
            spi_item->esp_info_spi_out = 0;
            break;
        }
    }
}

/* switch from Old SPI to New SPI (outbound SA) */
/* caller must delete the Old SPI */
void hip_update_switch_spi_out_deprecated_rekeying(hip_ha_t *entry,
                                                   uint32_t old_spi)
{
    struct hip_spi_in_item *spi_item;
    hip_list_t *item, *tmp;
    int i;

    _HIP_DEBUG("old_spi=0x%x\n", old_spi);
    list_for_each_safe(item, tmp, entry->spis_in_old, i)
    {
        spi_item = list_entry(item);
        _HIP_DEBUG("test item: spi=0x%x new_spi=0x%x seq_id=%u\n",
                   spi_item->spi, spi_item->new_spi, spi_item->seq_update_id);
        if (spi_item->spi == old_spi) {
            _HIP_DEBUG("switching\n");
            spi_item->spi     = spi_item->new_spi;
            spi_item->new_spi = 0;
            break;
        }
    }
}

/**
 * If @c test_new_spi is 1 then test new_spi instead of spi.
 * @return 1 if given SPI belongs to the SA having direction, else 0.
 */
int hip_update_exists_spi_deprecated_rekeying(hip_ha_t *entry, uint32_t spi,
                                              int direction, int test_new_spi)
{
    hip_list_t *item, *tmp;
    struct hip_spi_in_item *spi_item;
    int i;

    /* assumes locked entry  */

    _HIP_DEBUG("spi=0x%x direction=%d test_new_spi=%d\n",
               spi, direction, test_new_spi);

    if (direction == HIP_SPI_DIRECTION_IN) {
        list_for_each_safe(item, tmp, entry->spis_in_old, i)
        {
            spi_item = list_entry(item);
            _HIP_DEBUG("test item: spi_in=0x%x new_spi=0x%x\n",
                       spi_item->spi, spi_item->new_spi);
            if ((spi_item->spi == spi && !test_new_spi) ||
                (spi_item->new_spi == spi && test_new_spi)) {
                return 1;
            }
        }
    } else {
        list_for_each_safe(item, tmp, entry->spis_out_old, i)
        {
            spi_item = list_entry(item);
            _HIP_DEBUG("test item: spi_out=0x%x new_spi=0x%x\n",
                       spi_item->spi, spi_item->new_spi);
            if ((spi_item->spi == spi && !test_new_spi) ||
                (spi_item->new_spi == spi && test_new_spi)) {
                return 1;
            }
        }
    }
    HIP_DEBUG("not found\n");
    return 0;
}

/* if add is non-NULL, set addr as the default address for both
 * entry's default address and outbound SPI list's default address*/

/* if addr is null, select some address from the SPI list */
void hip_hadb_set_default_out_addr_deprecated(hip_ha_t *entry,
                                              struct in6_addr *addr)
{
#if 0
    HIP_DEBUG("\n");

    if (!spi_out) {
        HIP_ERROR("NULL spi_out\n");
        return;
    }

    if (addr) {
        HIP_DEBUG("testing, setting given address as default out addr\n");
        ipv6_addr_copy(&spi_out->preferred_address, addr);
        ipv6_addr_copy(&entry->peer_addr, addr);
    } else {
        /* useless ? */
        struct in6_addr a;
        int err = hip_hadb_select_spi_addr(entry, spi_out, &a);
        _HIP_DEBUG("setting address as default out addr\n");
        if (!err) {
            ipv6_addr_copy(&spi_out->preferred_address, &a);
            ipv6_addr_copy(&entry->peer_addr, &a);
            HIP_DEBUG("default out addr\n",
                      &entry->peer_addr);
        } else {HIP_ERROR("couldn't select and set preferred address\n");
        }
    }
    HIP_DEBUG("setting default SPI out to 0x%x\n", spi_out->spi);
    entry->default_spi_out = spi_out->spi;
#endif
}

/* works if update contains only one ESP_INFO */
int hip_update_get_spi_keymat_index_deprecated_rekeying(hip_ha_t *entry,
                                                        uint32_t peer_update_id)
{
    hip_list_t *item, *tmp;
    struct hip_spi_in_item *spi_item;
    int i;

    _HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
    list_for_each_safe(item, tmp, entry->spis_in_old, i)
    {
        spi_item = list_entry(item);
        _HIP_DEBUG("test item: spi_in=0x%x seq_update_id=%u keymat_index=%u\n",
                   spi_item->spi, item->seq_update_id, item->keymat_index);
        if (spi_item->seq_update_id == peer_update_id) {
            return spi_item->keymat_index;
        }
    }
    return 0;
}
