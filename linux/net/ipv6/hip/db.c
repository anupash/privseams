/*
 * HIP host id database and accessors.
 *
 * Authors: Janne Lundberg <jlu@tcs.hut.fi>
 *          Miika Komu <miika@iki.fi>
 *          Mika Kousa <mkousa@cc.hut.fi>
 *          Kristian Slavov <kslavov@hiit.fi>
 *
 */

#include <net/ipv6.h>

#include "db.h"
#include "misc.h"
#include "builder.h"
#include "socket.h"
#include "output.h"
#include "update.h"

/*
 * Do not access these databases directly: use the accessors in this file.
 */

HIP_INIT_DB(hip_peer_hostid_db, "peer_hid");
HIP_INIT_DB(hip_local_hostid_db, "local_hid");
HIP_INIT_DB(hip_local_eid_db, "local_eid");
HIP_INIT_DB(hip_peer_eid_db, "peer_eid");

/*
 *
 *
 * Static functions follow. These functions _MUST_ only be used in conjunction
 * with adequate locking. If the operation only fetches data, then READ lock is
 * enough. All contexts except the hip thread _SHOULD_ use READ locks.
 * The hip thread(s) is/are allowed to write to the databases. For this purpose
 * it/they will acquire the WRITE lock.
 *
 *
 */


/**
 * hip_uninit_hostid_db - uninitialize local/peer Host Id table
 * @db: Database structure to delete. 
 *
 * All elements of the @db are deleted. Since local and peer host id databases
 * include dynamically allocated host_id element, it is also freed.
 */
void hip_uninit_hostid_db(struct hip_db_struct *db)
{
	struct list_head *curr, *iter;
	struct hip_host_id_entry *tmp;
	unsigned long lf;

	HIP_WRITE_LOCK_DB(db);

	list_for_each_safe(curr,iter,&db->db_head) {
		tmp = list_entry(curr,struct hip_host_id_entry,next);
		if (tmp->host_id)
			kfree(tmp->host_id);
		kfree(tmp);
	}

	HIP_WRITE_UNLOCK_DB(db);
}

/**
 * hip_uninit_eid_db - uninitialize local/peer eid db
 * @db: Database structure to delete. 
 *
 * All elements of the @db are deleted.
 */
void hip_uninit_eid_db(struct hip_db_struct *db)
{
	struct list_head *curr, *iter;
	struct hip_host_id_entry *tmp;
	unsigned long lf;

	HIP_WRITE_LOCK_DB(db);

	list_for_each_safe(curr,iter,&db->db_head) {
		tmp = list_entry(curr, struct hip_host_id_entry, next);
		kfree(tmp);
	}

	HIP_WRITE_UNLOCK_DB(db);
}

void hip_uninit_all_eid_db(void)
{
	hip_uninit_eid_db(&hip_peer_eid_db);
	hip_uninit_eid_db(&hip_local_eid_db);
}


/**
 * hip_get_hostid_entry_by_lhi - finds the host id corresponding to the given @lhi
 * @db: Database to be searched. Usually either %HIP_DB_PEER_HID or %HIP_DB_LOCAL_HID
 * @lhi: the local host id to be searched 
 *
 * If lhi is null, finds the first used host id. 
 *
 * Returns: %NULL, if failed or non-NULL if succeeded.
 */
static 
struct hip_host_id_entry *hip_get_hostid_entry_by_lhi(struct hip_db_struct *db,
						      const struct hip_lhi *lhi)
{
	struct hip_host_id_entry *id_entry;

	/* should (id->used == used) test be binaric? */

	list_for_each_entry(id_entry,&db->db_head,next) {
		if ((lhi == NULL || hip_lhi_are_equal(&id_entry->lhi, lhi)))
			return id_entry;
	}

	return NULL;
}

static
struct hip_host_id_entry *hip_get_hostid_entry_by_lhi_and_algo(struct hip_db_struct *db,
							       const struct hip_lhi *lhi,
							       int algo)
{
	struct hip_host_id_entry *id_entry;

	list_for_each_entry(id_entry,&db->db_head,next) {
		if ((lhi == NULL || hip_lhi_are_equal(&id_entry->lhi, lhi)) &&
		    (hip_get_host_id_algo(*(&id_entry->host_id))==algo))
			return id_entry;
	}
	return NULL;
}

/*
 *
 *
 * Interface functions to access databases.
 *
 *
 *
 */

/***
 * ARG/TYPE arguments in following functions.
 *
 * arg is used as a database key. It is _REQUIRED_ to be of type
 * struct in6_addr *, _OR_ uint32. The first type is used IF AND ONLY IF,
 * the type argument equals to HIP_ARG_HIT. For all other values of
 * type, arg is assumed to be uint32 and the database is searched for
 * a corresponding own_spi.
 * In HIP_ARG_HIT case, the database is searched for corresponding
 * hit_peer field.
 ***
 */

/**
 * hip_uninit_host_id_dbs - Delete both host id databases
 *
 */
void hip_uninit_host_id_dbs(void)
{
	hip_uninit_hostid_db(&hip_local_hostid_db);
	hip_uninit_hostid_db(&hip_peer_hostid_db);
}


/**
 * hip_add_host_id - add the given HI into the database 
 * @db: Database structure
 * @lhi: HIT
 * @host_id: HI
 *
 * Checks for duplicates. If one is found, the current HI is _NOT_
 * stored.
 *
 * On success returns 0, otherwise an negative error value is returned.
 */
int hip_add_host_id(struct hip_db_struct *db,
		    const struct hip_lhi *lhi,
		    const struct hip_host_id *host_id)
{
	int err = 0;
	struct hip_host_id_entry *id_entry;
	struct hip_host_id_entry *old_entry;
	unsigned long lf;

	_HIP_HEXDUMP("adding host id",lhi,sizeof(struct hip_lhi));

	HIP_ASSERT(lhi != NULL);

	id_entry = kmalloc(sizeof(id_entry),GFP_KERNEL);
	if (id_entry == NULL) {
		HIP_ERROR("No memory available for host id\n");
		err = -ENOMEM;
		goto out_err;
	}

	id_entry->host_id = kmalloc(hip_get_param_total_len(host_id),
				    GFP_KERNEL);
	if (!id_entry->host_id) {
		HIP_ERROR("lhost_id mem alloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	/* copy lhi and host_id (host_id is already in network byte order) */
	id_entry->lhi.anonymous = lhi->anonymous;
	ipv6_addr_copy(&id_entry->lhi.hit, &lhi->hit);
	memcpy(id_entry->host_id, host_id, hip_get_param_total_len(host_id));

	HIP_WRITE_LOCK_DB(db);

	/* check for duplicates */
	old_entry = hip_get_hostid_entry_by_lhi(db, lhi);
	if (old_entry != NULL) {
		HIP_WRITE_UNLOCK_DB(db);
		HIP_ERROR("Trying to add duplicate lhi\n");
		err = -EEXIST;
		goto out_err;
	}

	list_add(&id_entry->next, &db->db_head);

	HIP_WRITE_UNLOCK_DB(db);

	return err;

 out_err:
	if (id_entry) {
		if (id_entry->host_id)
			kfree(id_entry->host_id);
		kfree(id_entry);
	}

	return err;
}

/**
 * hip_add_localhost_id - add a localhost id to the databases
 * @lhi: the HIT of the host
 * @host_id: the host id of the host
 *
 * Returns: zero on success, or negative error value on failure
 */
int hip_add_localhost_id(const struct hip_lhi *lhi,
			 const struct hip_host_id *host_id)
{
	return hip_add_host_id(&hip_local_hostid_db, lhi, host_id);
}


/**
 * hip_del_host_id - delete the given HI (network byte order) from the database.
 * @db: Database from which to delete
 * @lhi: the HIT to be deleted from the database
 *
 * Matches HIs based on the HIT
 *
 * Returns: returns 0, otherwise returns negative.
 */
int hip_del_host_id(struct hip_db_struct *db, struct hip_lhi *lhi)
{
	int err = -ENOENT;
	struct hip_host_id_entry *id = NULL;
	unsigned long lf;

	HIP_ASSERT(lhi != NULL);

	HIP_WRITE_LOCK_DB(db);

	id = hip_get_hostid_entry_by_lhi(db, lhi);
	if (id == NULL) {
		HIP_WRITE_UNLOCK_DB(db);
		HIP_ERROR("lhi not found\n");
		err = -ENOENT;
		return err;
	}

	list_del(&id->next);

	HIP_WRITE_UNLOCK_DB(db);

	/* free the dynamically reserved memory and
	   set host_id to null to signal that it is free */
	kfree(id->host_id);
	kfree(id);
	err = 0;
	return err;
}


/**
 * hip_copy_any_locahost_hit - Copy to the the @target the first 
 * local HIT that is found.
 * @target: Placeholder for the target
 *
 * Returns 0 if ok, and negative if failed.
 */
int hip_copy_any_localhost_hit(struct in6_addr *target)
{
	struct hip_host_id_entry *entry;
	int err = 0;
	unsigned long lf;

	HIP_READ_LOCK_DB(&hip_local_hostid_db);

	entry = hip_get_hostid_entry_by_lhi(&hip_local_hostid_db,NULL);
	if (!entry) {
		err=-ENOENT;
		goto out;
	}

	ipv6_addr_copy(target,&entry->lhi.hit);
	err = 0;

 out:
	HIP_READ_UNLOCK_DB(&hip_local_hostid_db);
	return err;
}

int hip_copy_any_localhost_hit_by_algo(struct in6_addr *target, int algo)
{
	struct hip_host_id_entry *entry;
	int err = 0;
	unsigned long lf;

	HIP_READ_LOCK_DB(&hip_local_hostid_db);

	entry = hip_get_hostid_entry_by_lhi_and_algo(&hip_local_hostid_db,NULL,algo);
	if (!entry) {
		err=-ENOENT;
		goto out;
	}
	
	ipv6_addr_copy(target,&entry->lhi.hit);
	err = 0;
	
 out:
	HIP_READ_UNLOCK_DB(&hip_local_hostid_db);
	return err;
}


/**
 * hip_copy_different_localhost_hit - Copy HIT that is not the same as the
 * argument HIT.
 * @target: Pointer to the area, where the differing HIT is copied.
 * @source: Pointer to the HIT that is used as a reference.
 *
 * If unable to find differing HIT, -ENOENT is returned. Otherwise 0.
 */
int hip_copy_different_localhost_hit(struct in6_addr *target,
				     struct in6_addr *source)
{
	struct hip_host_id_entry *entry;
	unsigned long lf;
	int err = -ENOENT;

	HIP_READ_LOCK_DB(&hip_local_hostid_db);

	list_for_each_entry(entry,&hip_local_hostid_db.db_head,next) {
		if (ipv6_addr_cmp(&entry->lhi.hit,source)) {
			HIP_DEBUG("Found different\n");
			ipv6_addr_copy(target,&entry->lhi.hit);
			err = 0;
			break;
		}
	}

	HIP_READ_UNLOCK_DB(&hip_local_hostid_db);
	return err;
} 

/* Get a LHI from given DB @db */
/* @res must be previously allocated */
/* Returns: 0 if a lhi was copied successfully to @res, < 0 otherwise. */
int hip_get_any_hit(struct hip_db_struct *db, struct hip_lhi *res,
		    uint8_t algo)
{
	struct hip_host_id_entry *entry;
	unsigned long lf;

	if (!res)
		return -EINVAL;
	if (list_empty(&db->db_head))
		return -EINVAL;
	
	HIP_READ_LOCK_DB(db);

	list_for_each_entry(entry, db->db_head.next, next) {
		if (hip_get_host_id_algo(entry->host_id) == algo) {
	                memcpy(res, &entry->lhi, sizeof(struct hip_lhi));
			HIP_READ_UNLOCK_DB(db);
			return 0;
		}
	}
	return -EINVAL;
}

int hip_get_any_local_hit(struct in6_addr *dst, uint8_t algo)
{
	struct hip_lhi lhi;

	if (!dst) {
		HIP_ERROR("NULL dst\n");
		return -EINVAL;
	}
	if (hip_get_any_hit(&hip_local_hostid_db, &lhi, algo) != 0) {
		HIP_ERROR("Could not retrieve any local HIT\n");
		return -ENOENT;
	}
	ipv6_addr_copy(dst, &lhi.hit);
	return 0;
}

int hip_hit_is_our(struct in6_addr *hit)
{
	struct hip_host_id_entry *entry;
	unsigned long lf;

	if (!hit) {
		HIP_ERROR("NULL hit\n");
		return 0;
	}

	HIP_READ_LOCK_DB(&hip_local_hostid_db);
	list_for_each_entry(entry, &hip_local_hostid_db.db_head, next) {
		if (!ipv6_addr_cmp(&entry->lhi.hit, hit)) {
			HIP_READ_UNLOCK_DB(&hip_local_hostid_db);
			return 1;
		}
	}
	HIP_READ_UNLOCK_DB(&hip_local_hostid_db);
	return 0;
}

/**
 * hip_get_host_id - Copies the host id into newly allocated memory
 * and returns it to the caller.
 * @db: Database
 * @lhi: HIT that is used as a database search key
 *
 * NOTE: Remember to free the returned host id structure.
 * This function should be only called by the HIP thread as it allocates
 * GFP_KERNEL memory. 
 * XXX: The memory that is allocated is 1024 bytes. If the key is longer,
 * we fail.
 * 
 * Returns hip_host_id structure, or %NULL, if the entry was not found.
 */
struct hip_host_id *hip_get_host_id(struct hip_db_struct *db, 
				    struct hip_lhi *lhi)
{

	struct hip_host_id_entry *tmp;
	struct hip_host_id *result;
	unsigned long lf;
	int t;

	result = kmalloc(1024, GFP_ATOMIC);
	if (!result) {
		HIP_ERROR("no memory\n");
		return NULL;
	}

	memset(result, 0, 1024);

	HIP_READ_LOCK_DB(db);

	tmp = hip_get_hostid_entry_by_lhi(db, lhi);
	if (!tmp) {
		HIP_READ_UNLOCK_DB(db);
		HIP_ERROR("No host id found\n");
		return NULL;
	}

	t = hip_get_param_total_len(tmp->host_id);
	if (t > 1024) {
		HIP_READ_UNLOCK_DB(db);
		kfree(result);
		return NULL;
	}

	memcpy(result, tmp->host_id, t);

	HIP_READ_UNLOCK_DB(db);

	return result;
}

struct hip_host_id *hip_get_host_id_by_algo(struct hip_db_struct *db, 
					    struct hip_lhi *lhi, int algo)
{

	struct hip_host_id_entry *tmp;
	struct hip_host_id *result;
	unsigned long lf;
	int t;

	result = kmalloc(1024, GFP_ATOMIC);
	if (!result) {
		HIP_ERROR("no memory\n");
		return NULL;
	}

	memset(result, 0, 1024);

	HIP_READ_LOCK_DB(db);

	tmp = hip_get_hostid_entry_by_lhi_and_algo(db, lhi, algo);
	if (!tmp) {
		HIP_READ_UNLOCK_DB(db);
		HIP_ERROR("No host id found\n");
		return NULL;
	}

	t = hip_get_param_total_len(tmp->host_id);
	if (t > 1024) {
		HIP_READ_UNLOCK_DB(db);
		kfree(result);
		return NULL;
	}

	memcpy(result, tmp->host_id, t);

	HIP_READ_UNLOCK_DB(db);

	return result;
}

/**
 * hip_get_any_localhost_host_id - get any Host ID of the local host
 * @algo: algorithm to use
 *
 * NOTE: Remember to free the host id structure after use.
 *
 * Returns pointer to newly allocated area that contains a localhost
 * HI. %NULL is returned is problems are encountered. 
 */
struct hip_host_id *hip_get_any_localhost_host_id(int algo)
{
	struct hip_host_id *result;
	/* XX TODO: use the algo */
	result = hip_get_host_id_by_algo(&hip_local_hostid_db,NULL, algo);
	return result;
}


/**
 * hip_get_any_localhost_dsa_public_key - Self documenting.
 *
 * NOTE: Remember to free the return value.
 *
 * Returns newly allocated area that contains the public key part of
 * the localhost host identity. %NULL is returned if errors detected.
 */
struct hip_host_id *hip_get_any_localhost_dsa_public_key(void)
{
	struct hip_host_id *tmp;
	hip_tlv_len_t len;
	uint16_t dilen;
	char *from, *to;
	u8 T;

	/* T could easily have been an int, since the compiler will
	   probably add 3 alignment bytes here anyway. */

	tmp = hip_get_host_id_by_algo(&hip_local_hostid_db,NULL,HIP_HI_DSA);
	if (tmp == NULL) {
		HIP_ERROR("No host id for localhost\n");
		return NULL;
	}

       /* check T, Miika won't like this */
	T = *((u8 *)(tmp + 1));
	if (T > 8) {
		HIP_ERROR("Invalid T-value in DSA key (0x%x)\n",T);
		kfree(tmp);
		return NULL;
	}

	if (T != 8) {
		HIP_DEBUG("T-value in DSA-key not 8 (0x%x)!\n",T);
	}

	_HIP_HEXDUMP("HOSTID...",tmp, hip_get_param_total_len(tmp));
	/* assuming all local keys are full DSA keys */
	len = hip_get_param_contents_len(tmp);

	_HIP_DEBUG("Host ID len before cut-off: %d\n",
		  hip_get_param_total_len(tmp));

	/* the secret component of the DSA key is always 20 bytes */

	tmp->hi_length = htons(ntohs(tmp->hi_length) - 20);

	_HIP_DEBUG("hi->hi_length=%d\n", htons(tmp->hi_length));

	/* Move the hostname 20 bytes earlier */

	dilen = ntohs(tmp->di_type_length) & 0x0FFF;

	to = ((char *)(tmp + 1)) - sizeof(struct hip_host_id_key_rdata) + ntohs(tmp->hi_length);
	from = to + 20;
	memmove(to, from, dilen);

	hip_set_param_contents_len(tmp, (len - 20));

	_HIP_DEBUG("Host ID len after cut-off: %d\n",
		  hip_get_param_total_len(tmp));

	/* make sure that the padding is zero (and not to reveal any bytes of the
	   private key */
	to = (char *)tmp + hip_get_param_contents_len(tmp) + sizeof(struct hip_tlv_common);
	memset(to, 0, 8);

	_HIP_HEXDUMP("HOSTID... (public)", tmp, hip_get_param_total_len(tmp));

	return tmp;
}


/**
 * hip_get_any_localhost_rsa_public_key - Self documenting.
 *
 * NOTE: Remember to free the return value.
 *
 * Returns newly allocated area that contains the public key part of
 * the localhost host identity. %NULL is returned if errors detected.
 */
struct hip_host_id *hip_get_any_localhost_rsa_public_key(void)
{
	struct hip_host_id *tmp;
	hip_tlv_len_t len;
	uint16_t dilen;
	char *from, *to;

	tmp = hip_get_host_id_by_algo(&hip_local_hostid_db,NULL, HIP_HI_RSA);
	if (tmp == NULL) {
		HIP_ERROR("No host id for localhost\n");
		return NULL;
	}

	/* XX TODO: check some value in the RSA key? */
      
	_HIP_HEXDUMP("HOSTID...",tmp, hip_get_param_total_len(tmp));
	
	len = hip_get_param_contents_len(tmp);

	_HIP_DEBUG("Host ID len before cut-off: %d\n",
		  hip_get_param_total_len(tmp));

	/* the secret component of the RSA key is always d+p+q bytes */
	/* note: it's assumed that RSA key length is 1024 bits */

	tmp->hi_length = htons(ntohs(tmp->hi_length) - (128+64+64));

	_HIP_DEBUG("hi->hi_length=%d\n", htons(tmp->hi_length));

	/* Move the hostname d+p+q bytes earlier */

	dilen = ntohs(tmp->di_type_length) & 0x0FFF;

	HIP_DEBUG("dilen: %d\n", dilen);

	to = ((char *)(tmp + 1)) - sizeof(struct hip_host_id_key_rdata) + ntohs(tmp->hi_length);
	from = to + (128+64+64); /* d, p, q*/
	memmove(to, from, dilen);

	hip_set_param_contents_len(tmp, (len - (128+64+64)));

	HIP_DEBUG("Host ID len after cut-off: %d\n",
		  hip_get_param_total_len(tmp));

	/* make sure that the padding is zero (and not to reveal any bytes of
	   the private key */
	to = (char *)tmp + hip_get_param_contents_len(tmp) +
	  sizeof(struct hip_tlv_common);
	memset(to, 0, 8);

	_HIP_HEXDUMP("HOSTID... (public)", tmp, hip_get_param_total_len(tmp));

	return tmp;

}

/**
 * hip_get_any_localhost_public_key - Self documenting.
 * @algo: algorithm to use
 *
 * NOTE: Remember to free the return value.
 *
 * Returns newly allocated area that contains the public key part of
 * the localhost host identity. %NULL is returned if errors detected.
 */
struct hip_host_id *hip_get_any_localhost_public_key(int algo) {
	
	struct hip_host_id *hi = NULL;

	if(algo == HIP_HI_DSA) {
		hi = hip_get_any_localhost_dsa_public_key();
	} else if (algo == HIP_HI_RSA) {
		hi = hip_get_any_localhost_rsa_public_key();
	} else {
	  HIP_ERROR("unknown hi algo: (%d)",algo);
	}
	return hi;
}


/* PROC_FS FUNCTIONS */


#ifdef CONFIG_PROC_FS

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

#endif /* CONFIG_PROC_FS */


struct hip_eid_db_entry *hip_db_find_eid_entry_by_hit_no_lock(struct hip_db_struct *db,
						     const struct hip_lhi *lhi)
{
	struct hip_eid_db_entry *entry;

	HIP_DEBUG("\n");

	list_for_each_entry(entry, &db->db_head, next) {
		/* XX TODO: Skip the anonymous bit. Is it ok? */
		if (!ipv6_addr_cmp(&entry->lhi.hit,
				   (struct in6_addr *) &lhi->hit))
			return entry;
	}

	return NULL;
}

struct hip_eid_db_entry *hip_db_find_eid_entry_by_eid_no_lock(struct hip_db_struct *db,
						const struct sockaddr_eid *eid)
{
	struct hip_eid_db_entry *entry;

	list_for_each_entry(entry, &db->db_head, next) {
		HIP_DEBUG("comparing %d with %d\n",
			  ntohs(entry->eid.eid_val), ntohs(eid->eid_val));
		if (entry->eid.eid_val == eid->eid_val)
			    return entry;
	}

	return NULL;
}

int hip_db_set_eid(struct sockaddr_eid *eid,
		   const struct hip_lhi *lhi,
		   const struct hip_eid_owner_info *owner_info,
		   int is_local)
{
	struct hip_db_struct *db;
	int err = 0;
	unsigned long lf;
	struct hip_eid_db_entry *entry = NULL;

	HIP_DEBUG("Accessing %s eid db\n", ((is_local) ? "local" : "peer"));

	db = (is_local) ? &hip_local_eid_db : &hip_peer_eid_db;

	HIP_WRITE_LOCK_DB(db);

	entry = hip_db_find_eid_entry_by_hit_no_lock(db, lhi);
	if (!entry) {
		entry = kmalloc(sizeof(struct hip_eid_db_entry), GFP_KERNEL);
		if (!entry) {
			err = -ENOMEM;
			goto out_err;
		}

		entry->eid.eid_val = ((is_local) ?
			htons(hip_create_unique_local_eid()) :
			htons(hip_create_unique_peer_eid()));
		entry->eid.eid_family = PF_HIP;
		memcpy(eid, &entry->eid, sizeof(struct sockaddr_eid));

		HIP_DEBUG("Generated eid val %d\n", entry->eid.eid_val);

		memcpy(&entry->lhi, lhi, sizeof(struct hip_lhi));
		memcpy(&entry->owner_info, owner_info,
		       sizeof(struct hip_eid_owner_info));

		/* Finished. Add the entry to the list. */
		list_add(&entry->next, &db->db_head);
	} else {
		/* XX TODO: Ownership is not changed here; should it? */
		memcpy(eid, &entry->eid, sizeof(struct sockaddr_eid));
	}

 out_err:
	HIP_WRITE_UNLOCK_DB(db);

	return err;
}

int hip_db_set_my_eid(struct sockaddr_eid *eid,
		      const struct hip_lhi *lhi,
		      const struct hip_eid_owner_info *owner_info)
{
	return hip_db_set_eid(eid, lhi, owner_info, 1);
}

int hip_db_set_peer_eid(struct sockaddr_eid *eid,
			const struct hip_lhi *lhi,
			const struct hip_eid_owner_info *owner_info)
{
	return hip_db_set_eid(eid, lhi, owner_info, 0);
}

int hip_db_get_lhi_by_eid(const struct sockaddr_eid *eid,
			  struct hip_lhi *lhi,
			  struct hip_eid_owner_info *owner_info,
			  int is_local)
{
	struct hip_db_struct *db;
	int err = 0;
	unsigned long lf;
	struct hip_eid_db_entry *entry = NULL;

	HIP_DEBUG("Accessing %s eid db\n", ((is_local) ? "local" : "peer"));

	db = (is_local) ? &hip_local_eid_db : &hip_peer_eid_db;

	HIP_READ_LOCK_DB(db);

	entry = hip_db_find_eid_entry_by_eid_no_lock(db, eid);
	if (!entry) {
		err = -ENOENT;
		goto out_err;
	}

	memcpy(lhi, &entry->lhi, sizeof(struct hip_lhi));
	memcpy(owner_info, &entry->owner_info,
	       sizeof(struct hip_eid_owner_info));

 out_err:
	HIP_READ_UNLOCK_DB(db);

	return err;

}

int hip_db_get_peer_lhi_by_eid(const struct sockaddr_eid *eid,
			  struct hip_lhi *lhi,
			  struct hip_eid_owner_info *owner_info)
{
	return hip_db_get_lhi_by_eid(eid, lhi, owner_info, 0);
}

int hip_db_get_my_lhi_by_eid(const struct sockaddr_eid *eid,
			     struct hip_lhi *lhi,
			     struct hip_eid_owner_info *owner_info)
{
	return hip_db_get_lhi_by_eid(eid, lhi, owner_info, 1);
}

#undef HIP_READ_LOCK_DB
#undef HIP_WRITE_LOCK_DB
#undef HIP_READ_UNLOCK_DB
#undef HIP_WRITE_UNLOCK_DB
