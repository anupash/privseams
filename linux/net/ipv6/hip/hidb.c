/*
 * HIP host id database and accessors.
 *
 * Authors: Janne Lundberg <jlu@tcs.hut.fi>
 *          Miika Komu <miika@iki.fi>
 *          Mika Kousa <mkousa@cc.hut.fi>
 *          Kristian Slavov <kslavov@hiit.fi>
 *
 */

#include "hidb.h"

/*
 * Do not access these databases directly: use the accessors in this file.
 */

/* XX FIXME: these should hashes instead of plain linked lists */
HIP_INIT_DB(hip_peer_hostid_db, "peer_hid");
HIP_INIT_DB(hip_local_hostid_db, "local_hid");

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
			HIP_FREE(tmp->host_id);
		HIP_FREE(tmp);
	}

	HIP_WRITE_UNLOCK_DB(db);
}


/**
 * hip_get_hostid_entry_by_lhi - finds the host id corresponding to the given @lhi
 * @db: Database to be searched. Usually either %HIP_DB_PEER_HID or %HIP_DB_LOCAL_HID
 * @lhi: the local host id to be searched 
 *
 * If lhi is null, finds the first used host id. 
 * If algo is HIP_ANY_ALGO, ignore algore comparison.
 *
 * Returns: %NULL, if failed or non-NULL if succeeded.
 */
static
struct hip_host_id_entry *hip_get_hostid_entry_by_lhi_and_algo(struct hip_db_struct *db,
							       const struct hip_lhi *lhi,
							       int algo)
{
	struct hip_host_id_entry *id_entry;

	list_for_each_entry(id_entry, &db->db_head, next) {
	  if ((lhi == NULL || hip_lhi_are_equal(&id_entry->lhi, lhi)) &&
	      (algo == HIP_ANY_ALGO || (hip_get_host_id_algo(*(&id_entry->host_id)) == algo)))
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
 * @insert the handler to call right after the host id is added
 * @remove the handler to call right before the host id is removed
 * @arg argument passed for the handlers
 *
 * Checks for duplicates. If one is found, the current HI is _NOT_
 * stored.
 *
 * On success returns 0, otherwise an negative error value is returned.
 */
int hip_add_host_id(struct hip_db_struct *db,
		    const struct hip_lhi *lhi,
		    const struct hip_host_id *host_id,
		    int (*insert)(void **arg),
		    int (*remove)(void **arg),
		    void *arg)
{
	int err = 0;
	struct hip_host_id_entry *id_entry;
	struct hip_host_id_entry *old_entry;
	unsigned long lf;

	_HIP_HEXDUMP("adding host id",lhi,sizeof(struct hip_lhi));

	HIP_ASSERT(lhi != NULL);

	id_entry = (struct hip_host_id_entry *) HIP_MALLOC(sizeof(id_entry),
							  GFP_KERNEL);
	if (id_entry == NULL) {
		HIP_ERROR("No memory available for host id\n");
		err = -ENOMEM;
		goto out_err;
	}

	id_entry->host_id = (struct hip_host_id *)
		HIP_MALLOC(hip_get_param_total_len(host_id),
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
	old_entry = hip_get_hostid_entry_by_lhi_and_algo(db, lhi, HIP_ANY_ALGO);
	if (old_entry != NULL) {
		HIP_WRITE_UNLOCK_DB(db);
		HIP_ERROR("Trying to add duplicate lhi\n");
		err = -EEXIST;
		goto out_err;
	}

	id_entry->insert = insert;
	id_entry->remove = remove;
	id_entry->arg = arg;

	list_add(&id_entry->next, &db->db_head);

	HIP_WRITE_UNLOCK_DB(db);

	if (insert) 
		insert(&arg);

	return err;

 out_err:
	if (id_entry) {
		if (id_entry->host_id)
			HIP_FREE(id_entry->host_id);
		HIP_FREE(id_entry);
	}

	return err;
}

static int hip_default_hi_initializer(void **arg) {
	struct in6_addr hit_our;
	int err = 0;

	HIP_DEBUG("Generating a new R1 now.\n");
	
	if (hip_get_any_localhost_hit(&hit_our,
				      HIP_HI_DEFAULT_ALGO) < 0) {
		HIP_ERROR("Didn't find a HIT for R1 precreation.\n");
		err = -EINVAL;
		goto out_err;
	}

	/* XX FIX: only RSA R1s are precreated - solved on the multi branch */
       	if (!hip_precreate_r1(&hit_our)) {
		HIP_ERROR("Unable to precreate R1s.\n");
		err = -ENOENT;
		goto out_err;
	}

 out_err:
	return err;
}

/**
 * hip_handle_local_add_hi - handle adding of a localhost host identity
 * @input: contains the hi parameter in fqdn format (includes private key)
 *
 * Returns: zero on success, or negative error value on failure
 */
int hip_handle_add_local_hi(const struct hip_common *input)
{
	int err = 0;
	struct hip_host_id *dsa_host_identity, *rsa_host_identity = NULL;
	struct hip_lhi dsa_lhi, rsa_lhi;
	
	HIP_DEBUG("\n");

	if ((err = hip_get_msg_err(input)) != 0) {
		HIP_ERROR("daemon failed (%d)\n", err);
		goto out_err;
	}

	_HIP_DUMP_MSG(response);

	dsa_host_identity = hip_get_nth_param(input, HIP_PARAM_HOST_ID, 1);
        if (!dsa_host_identity) {
		HIP_ERROR("no dsa host identity pubkey in response\n");
		err = -ENOENT;
		goto out_err;
	}

	rsa_host_identity = hip_get_nth_param(input, HIP_PARAM_HOST_ID, 2);
        if (!rsa_host_identity) {
		HIP_ERROR("no rsa host identity pubkey in response\n");
		err = -ENOENT;
		goto out_err;
	}

	_HIP_HEXDUMP("rsa host id\n", rsa_host_identity,
		    hip_get_param_total_len(rsa_host_identity));

	err = hip_private_host_id_to_hit(dsa_host_identity, &dsa_lhi.hit,
					 HIP_HIT_TYPE_HASH126);
	if (err) {
		HIP_ERROR("dsa host id to hit conversion failed\n");
		goto out_err;
	}

	err = hip_private_host_id_to_hit(rsa_host_identity, &rsa_lhi.hit,
					 HIP_HIT_TYPE_HASH126);
	if (err) {
		HIP_ERROR("rsa host id to hit conversion failed\n");
		goto out_err;
	}

	/* XX FIX: Note: currently the order of insertion of host ids makes a
	   difference. */
	err = hip_add_host_id(HIP_DB_LOCAL_HID, &rsa_lhi, rsa_host_identity, 
			      hip_default_hi_initializer, NULL, NULL);
	if (err) {
		HIP_ERROR("adding of local host identity failed\n");
		goto out_err;
	}

	err = hip_add_host_id(HIP_DB_LOCAL_HID, &dsa_lhi, dsa_host_identity, 
			      hip_default_hi_initializer, NULL, NULL);
	if (err) {
		HIP_ERROR("adding of local host identity failed\n");
		goto out_err;
	}

	HIP_DEBUG("Adding of HIP localhost identities was successful\n");

        /* XX TODO: precreate R1s for both algorithms, not just the default */ 
 out_err:
	
	return err;
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

	id = hip_get_hostid_entry_by_lhi_and_algo(db, lhi, HIP_ANY_ALGO);
	if (id == NULL) {
		HIP_WRITE_UNLOCK_DB(db);
		HIP_ERROR("lhi not found\n");
		err = -ENOENT;
		return err;
	}

	list_del(&id->next);

	HIP_WRITE_UNLOCK_DB(db);

	/* Call the handler to execute whatever required after the
           host id is no more in the database */
	if (id->remove) 
		id->remove(&id->arg);

	/* free the dynamically reserved memory and
	   set host_id to null to signal that it is free */
	HIP_FREE(id->host_id);
	HIP_FREE(id);
	err = 0;
	return err;
}

/**
 * hip_get_any_locahost_hit - Copy to the the @target the first 
 * local HIT that is found.
 * @target: Placeholder for the target
 * @param algo the algoritm to match, but if HIP_ANY_ALGO comparison is ignored.
 *
 * Returns 0 if ok, and negative if failed.
 */
int hip_get_any_localhost_hit(struct in6_addr *target, int algo)
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
 * NOTE: Remember to free the host id structure after use.
 *
 * Returns pointer to newly allocated area that contains a localhost
 * HI. %NULL is returned is problems are encountered. 
 *
 * NOTE: The memory that is allocated is 1024 bytes. If the key is longer,
 * we fail.
 *
 * @param lhi HIT to match, if null, any.
 * @param algo algorithm to match, if HIP_ANY_ALGO, any.
 */
struct hip_host_id *hip_get_host_id(struct hip_db_struct *db, 
				    struct hip_lhi *lhi, int algo)
{
	struct hip_host_id_entry *tmp;
	struct hip_host_id *result;
	unsigned long lf;
	int t;

	result = (struct hip_host_id *)HIP_MALLOC(1024, GFP_ATOMIC);
	if (!result) {
		HIP_ERROR("Out of memory.\n");
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
		HIP_FREE(result);
		return NULL;
	}

	memcpy(result, tmp->host_id, t);

	HIP_READ_UNLOCK_DB(db);

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

	tmp = hip_get_host_id(&hip_local_hostid_db,NULL,HIP_HI_DSA);
	if (tmp == NULL) {
		HIP_ERROR("No host id for localhost\n");
		return NULL;
	}

       /* check T, Miika won't like this */
	T = *((u8 *)(tmp + 1));
	if (T > 8) {
		HIP_ERROR("Invalid T-value in DSA key (0x%x)\n",T);
		HIP_FREE(tmp);
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

	tmp = hip_get_host_id(&hip_local_hostid_db,NULL, HIP_HI_RSA);
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
 *
 * NOTE: Remember to free the return value.
 *
 * Returns newly allocated area that contains the public key part of
 * the localhost host identity. %NULL is returned if errors detected.
 */
struct hip_host_id *hip_get_any_localhost_public_key(int algo) 
{
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

#undef HIP_READ_LOCK_DB
#undef HIP_WRITE_LOCK_DB
#undef HIP_READ_UNLOCK_DB
#undef HIP_WRITE_UNLOCK_DB
