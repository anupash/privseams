#include "proc.h"

#ifdef CONFIG_PROC_FS

#ifndef CONFIG_HIP_USERSPACE
typedef struct {
	char *page;
	int count;
	int len;
	int i; /* counter */
} hip_proc_opaque_t;

static struct proc_dir_entry *hip_proc_root = NULL;

static int hip_proc_hadb_state_func(hip_ha_t *entry, void *opaque)
{
	hip_proc_opaque_t *op = (hip_proc_opaque_t *)opaque;
	char *esp_transforms[] = { "none/reserved", "aes-sha1", "3des-sha1", "3des-md5",
				   "blowfish-sha1", "null-sha1", "null-md5" };
	char addr_str[INET6_ADDRSTRLEN];
	char *page = op->page;
	int len = op->len;
	int count = op->count;
	int i = op->i;

	HIP_LOCK_HA(entry);

	if ( (len += snprintf(page+len, count-len, "%s 0x%x %d 0x%x",
			      hip_state_str(entry->state),
			      entry->hastate, 
			      atomic_read(&entry->refcnt), 
			      entry->peer_controls)) >= count)
		goto error;

	hip_in6_ntop(&entry->hit_our, addr_str);
	if ( (len += snprintf(page+len, count-len, " %s", addr_str)) >= count)
		goto error;

	hip_in6_ntop(&entry->hit_peer, addr_str);
	if ( (len += snprintf(page+len, count-len, " %s", addr_str)) >= count)
		goto error;

       if ( (len += snprintf(page+len, count-len,
			     " 0x%08x 0x%08x 0x%08x %s",
			     entry->default_spi_out, entry->lsi_our,
			     entry->lsi_peer,
			     entry->esp_transform <=
			     (sizeof(esp_transforms)/sizeof(esp_transforms[0]))
			     ? esp_transforms[entry->esp_transform] :
			     "UNKNOWN")) >= count)
	       goto error;

	if ( (len += snprintf(page+len, count-len,
			      " 0x%llx %u %u %u %u %u\n",
			      entry->birthday, 
			      entry->current_keymat_index,
			      entry->keymat_calc_index, entry->update_id_in,
			      entry->update_id_out, entry->dh_shared_key_len )) >= count)
		goto error;

	if (len >= count)
		goto error;

	HIP_UNLOCK_HA(entry);

	op->len = len;
	op->count = count;
	op->i = i;
	return 0;

 error:
	HIP_UNLOCK_HA(entry);
	HIP_DEBUG("PROC read max len exceeded\n");
	return -1;
}


static int hip_proc_read_hadb_peer_addrs_func(hip_ha_t *entry, void *opaque)
{
	hip_proc_opaque_t *op = (hip_proc_opaque_t *)opaque;
	struct timeval now, addr_age;
	char addr_str[INET6_ADDRSTRLEN];
	struct hip_peer_addr_list_item *s;
	int i = op->i;
	char *page = op->page;
	int len = op->len;
	int count = op->count;
	struct hip_spi_out_item *spi_out, *spi_tmp;
	const char *state_name[] = { "NONE", "UNVERIFIED", "ACTIVE", "DEPRECATED" };

	do_gettimeofday(&now);

	HIP_LOCK_HA(entry);

	hip_in6_ntop(&entry->hit_peer, addr_str);
	if ( (len += snprintf(page+len, count-len, "HIT %s", addr_str)) >= count)
		goto error;

	if (entry->default_spi_out == 0) {
		/* extra check for addr_any ? */
		hip_in6_ntop(&entry->bex_address, addr_str);
		if ( (len += snprintf(page+len, count-len,
				      "\n SPI 0x0\n  %s", addr_str)) >= count)
			goto error;
	}

	list_for_each_entry_safe(spi_out, spi_tmp, &entry->spis_out, list) {
		int n_addrs = 0;

		if ( (len += snprintf(page+len, count-len,
				      "\n SPI 0x%x", spi_out->spi)) >= count)
			goto error;

		if (spi_out->spi == entry->default_spi_out &&
		    (len += snprintf(page+len, count-len, " preferred")) >= count)
			goto error;

		list_for_each_entry(s, &spi_out->peer_addr_list, list) {
			n_addrs++;
			hip_in6_ntop(&s->address, addr_str);
			hip_timeval_diff(&now, &s->modified_time, &addr_age);
			if ( (len += snprintf(page+len, count-len,
					      "\n  %s state=%s lifetime=0x%x "
					      "age=%ld.%01ld seq=%u REA_preferred=%d",
					      addr_str, state_name[s->address_state],
					      s->lifetime, addr_age.tv_sec,
					      addr_age.tv_usec / 100000 /* show 1/10th sec */,
					      s->seq_update_id, s->is_preferred)
				     ) >= count)
				goto error;

		if (!ipv6_addr_cmp(&s->address, &spi_out->preferred_address) &&
		    (len += snprintf(page+len, count-len, " preferred")) >= count)
			goto error;

			i++;
		}

		if (n_addrs == 0 && (len += snprintf(page+len, count-len, "\n  no addresses")) >= count)
			goto error;
	}

	if ( (len += snprintf(page+len, count-len, "\n")) >= count)
		goto error;

	HIP_UNLOCK_HA(entry);

	op->len = len;
	op->count = count;
	op->i = i;
	return 0;
 error:
	HIP_UNLOCK_HA(entry);
	HIP_DEBUG("PROC read peer addresses buffer exceeded\n");
	return -1;
}

/**
 * hip_proc_read_hadb_state - debug function for dumping hip_sdb_state
 * @page: where dumped data is written to
 * @start: ignored
 * @off: ignored
 * @count: how many bytes to read
 * @eof: pointer where end of file flag is stored, always set to 1
 * @data: ignored
 *
 * hip_hadb_state can be dumped from file /proc/net/hip/sdb_state
 *
 * Returns: number of bytes written to @page.
 */
int hip_proc_read_hadb_state(char *page, char **start, off_t off,
			     int count, int *eof, void *data)
{
	hip_proc_opaque_t ps;
	int fail;

	ps.page = page;
	ps.count = count;

	ps.len = snprintf(page, count,
		       "state hastate refcnt peer_controls hit_our hit_peer "
		       "default_spi_out lsi_our lsi_peer esp_transform "
		       "birthday keymat_index keymat_calc_index "
		       "update_id_in update_id_out dh_len\n");

	if (ps.len >= count) {
		fail = 1;
		goto err;
	}

	*eof = 1;
	fail = hip_for_each_ha(hip_proc_hadb_state_func, &ps);

 err:
	if (fail) {
		page[ps.count-1] = '\0';
		ps.len = ps.count;
	} else
		page[ps.len] = '\0';

	return ps.len;
}


/**
 * hip_proc_read_hadb_peer_addrs - dump properties of IPv6 addresses of every peer
 * @page: where dumped data is written to
 * @start: ignored
 * @off: ignored
 * @count: how many bytes to read
 * @eof: pointer where end of file flag is stored, always set to 1
 * @data: ignored
 *
 * This debug function lists every IPv6 address and their properties
 * for every peer. The list can be dumped from from file
 * /proc/net/hip/sdb_peer_addrs
 *
 * Returns: number of bytes written to @page.
 */
int hip_proc_read_hadb_peer_addrs(char *page, char **start, off_t off,
				  int count, int *eof, void *data)
{
	hip_proc_opaque_t ps;
	int fail;

	ps.page = page;
	ps.count = count;
	ps.len = 0;
	*eof = 1;

	fail = hip_for_each_ha(hip_proc_read_hadb_peer_addrs_func, &ps);
	if (fail) {
		page[ps.count-1] = '\0';
		ps.len = ps.count;
	} else
		page[ps.len] = '\0';

	return ps.len;
}

/**
 * hip_proc_read_lhi - debug function for dumping LHIs from procfs file /proc/net/hip/lhi
 * @page: where dumped data is written to
 * @start: ignored
 * @off: ignored
 * @count: how many bytes to read
 * @eof: pointer where end of file flag is stored, always set to 1
 * @data: ignored
 *
 * Returns: number of bytes written to @page.
 */
int hip_proc_read_lhi(char *page, char **start, off_t off,
		      int count, int *eof, void *data) 
{
	/* XX: Called with sdb lock held ? */

        int len = 0;
	int i;
	unsigned long lf = 0;
	struct hip_host_id_entry *item;
	char in6buf[INET6_ADDRSTRLEN];

	_HIP_DEBUG("off=%d count=%d eof=%d\n", (int) off, count, *eof);


	len += snprintf(page, count, "# used type algo HIT\n");
	if (len >= count)
		goto err;

	HIP_READ_LOCK_DB(&hip_local_hostid_db);

	i=0;
	list_for_each_entry(item,&hip_local_hostid_db.db_head,next) {
		hip_in6_ntop(&item->lhi.hit, in6buf);
		len += snprintf(page+len, count-len, "%d %d %s %s %s\n",
				++i,
				1,
				item->lhi.anonymous?"anon":"public",
				hip_algorithm_to_string
				(hip_get_host_id_algo(item->host_id)),
				in6buf);
		if (len >= count)
			break;
	}

	HIP_READ_UNLOCK_DB(&hip_local_hostid_db);

	if (len >= count) {
		page[count-1] = '\0';
		len = count;
	} else {
		page[len] = '\0';
	}

 err:
	*eof = 1;
        return(len);
}

#if 0
int hip_proc_send_update(char *page, char **start, off_t off,
			 int count, int *eof, void *data)
{
	HIP_DEBUG("\n");
	hip_send_update_all(NULL, 0, 0, 0);
	*eof = 1;

	return 0;
}

/* only during testing */
int hip_proc_send_notify(char *page, char **start, off_t off,
			 int count, int *eof, void *data)
{
	hip_send_notify_all();
	*eof = 1;
	return 0;
}
#endif
#endif /* CONFIG_HIP_USERSPACE */
/**
 * hip_init_procfs - initialize HIP procfs support
 *
 * Returns: 1 if procfs was initialized successfully, otherwise -1.
 */
int hip_init_procfs(void)
{
#ifndef CONFIG_HIP_USERSPACE
	HIP_DEBUG("procfs init\n");
	hip_proc_root = create_proc_entry("hip", S_IFDIR, proc_net);
	if (!hip_proc_root)
		return -1;

	/* todo: set file permission modes */
	if (!create_proc_read_entry("lhi", 0, hip_proc_root,
				    hip_proc_read_lhi, NULL))
		goto out_err_root;
	if (!create_proc_read_entry("sdb_state", 0, hip_proc_root,
			       hip_proc_read_hadb_state, NULL))
		goto out_err_lhi;
	if (!create_proc_read_entry("sdb_peer_addrs", 0, hip_proc_root,
			       hip_proc_read_hadb_peer_addrs, NULL))
		goto out_err_sdb_state;
#if 0
	/* a simple way to trigger sending of UPDATE packet to all peers */
	if (!create_proc_read_entry("send_update", 0, hip_proc_root,
			       hip_proc_send_update, NULL))
		goto out_err_peer_addrs;
	/* for testing dummy NOTIFY packets */
	if (!create_proc_read_entry("send_notify", 0, hip_proc_root,
			       hip_proc_send_notify, NULL))
		goto out_err_send_update;
#endif

	HIP_DEBUG("profcs init successful\n");
#endif /* CONFIG_HIP_USERSPACE */
	return 1;

#ifndef CONFIG_HIP_USERSPACE
#if 0
 out_err_send_update:
	remove_proc_entry("send_update", hip_proc_root);
 out_err_peer_addrs:
	remove_proc_entry("sdb_peer_addrs", hip_proc_root);
#endif
 out_err_sdb_state:
	remove_proc_entry("sdb_state", hip_proc_root);
 out_err_lhi:
	remove_proc_entry("lhi", hip_proc_root);
 out_err_root:
	remove_proc_entry("net/hip", NULL);

	HIP_ERROR("profcs init failed\n");
	return -1;
#endif /* CONFIG_HIP_USERSPACE */
}

/**
 * hip_uninit_procfs - uninitialize HIP procfs support
 */
void hip_uninit_procfs(void)
{
#ifndef CONFIG_HIP_USERSPACE
	HIP_DEBUG("\n");
	remove_proc_entry("lhi", hip_proc_root);
	remove_proc_entry("sdb_state", hip_proc_root);
	remove_proc_entry("sdb_peer_addrs", hip_proc_root);
#if 0
	remove_proc_entry("send_update", hip_proc_root);
	remove_proc_entry("send_notify", hip_proc_root);
#endif
	remove_proc_entry("hip", proc_net);
#endif /* CONFIG_HIP_USERSPACE */
}

#endif /* CONFIG_PROC_FS */
