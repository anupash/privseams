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

	list_add(&id_entry->next, &db->db_head);

	HIP_WRITE_UNLOCK_DB(db);

	return err;

 out_err:
	if (id_entry) {
		if (id_entry->host_id)
			HIP_FREE(id_entry->host_id);
		HIP_FREE(id_entry);
	}

	return err;
}

#ifdef CONFIG_HIP_HI3
/* 
 * i3 callbacks for trigger management
 */
static void constraint_failed(cl_trigger *t, void *data, void *fun_ctx) {
	/* This should never occur if the infrastructure works */
	HIP_ERROR("Trigger constraint failed\n");
}

static void trigger_inserted(cl_trigger *t, void *data, void *fun_ctx) {	
	HIP_DEBUG("Trigger inserted\n");
}

static void trigger_failure(cl_trigger *t, void *data, void *fun_ctx) {
	/* FIXME: A small delay before trying again? */
	HIP_ERROR("Trigger failed, reinserting...\n");
	
	/* Reinsert trigger */
	cl_insert_trigger(t, 0);
}
#endif

#ifdef CONFIG_HIP_HI3
static int insert_trigger(struct in6_addr *hit, 
			  struct hip_host_id_entry *entry) {
	ID id, ida;
	cl_trigger *t1, *t2;
	Key key;

	HIP_ASSERT(entry);

	/*
	 * Create and insert triggers (id, ida), and (ida, R), respectively.
	 * All triggers are r-constrained (right constrained)
	 */
	bzero(&id, ID_LEN);
	memcpy(&id, hit, sizeof(hit));
	get_random_bytes(id.x, ID_LEN);	
#if 0
 FIXME: should these be here or not...
	cl_set_private_id(&id);
	cl_set_private_id(&ida);
#endif 

	/* Note: ida will be updated as ida.key = h_r(id.key) */
	t1 = cl_create_trigger_id(&id, ID_LEN_BITS, &ida,
				  CL_TRIGGER_CFLAG_R_CONSTRAINT);
	t2  = cl_create_trigger(&ida, ID_LEN_BITS, &key,
				CL_TRIGGER_CFLAG_R_CONSTRAINT);

	/* associate callbacks with the inserted trigger */
	cl_register_trigger_callback(t2, CL_CBK_TRIGGER_CONSTRAINT_FAILED,
				     constraint_failed, NULL);
	cl_register_trigger_callback(t2, CL_CBK_RECEIVE_PAYLOAD,
				     hip_inbound, NULL);
	cl_register_trigger_callback(t2, CL_CBK_TRIGGER_INSERTED,
				     trigger_inserted, NULL);
	cl_register_trigger_callback(t2, CL_CBK_TRIGGER_REFRESH_FAILED,
				     trigger_failure, NULL);

	/* Insert triggers */
	cl_insert_trigger(t2, 0);
	cl_insert_trigger(t1, 0);

	entry->t1 = t1;
	entry->t2 = t2;
}
#endif       

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
	struct in6_addr hit_our;
	
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
	err = hip_add_host_id(HIP_DB_LOCAL_HID, &rsa_lhi, rsa_host_identity);
	if (err) {
		HIP_ERROR("adding of local host identity failed\n");
		goto out_err;
	}

	err = hip_add_host_id(HIP_DB_LOCAL_HID, &dsa_lhi, dsa_host_identity);
	if (err) {
		HIP_ERROR("adding of local host identity failed\n");
		goto out_err;
	}

	HIP_DEBUG("Adding of HIP localhost identities was successful\n");

	HIP_DEBUG("hip: Generating a new R1 now\n");
	
        /* XX TODO: precreate R1s for both algorithms, not just the default */ 
	if (hip_get_any_localhost_hit(&hit_our,
				      HIP_HI_DEFAULT_ALGO) < 0) {
		HIP_ERROR("Didn't find HIT for R1 precreation\n");
		err = -EINVAL;
		goto out_err;
	}

	/* XX FIX: only RSA R1s are precreated - solved on the multi branch */
       	if (!hip_precreate_r1(&hit_our)) {
		HIP_ERROR("Unable to precreate R1s... failing\n");
		err = -ENOENT;
		goto out_err;
	}

#ifdef CONFIG_HIP_HI3
	insert_trigger(&rsa_lhi.hit, (struct hip_host_id_entry *)
		       hip_get_hostid_entry_by_lhi(&hip_local_hostid_db, &rsa_lhi.hit));
	insert_trigger(&dsa_lhi.hit, (struct hip_host_id_entry *)
		       hip_get_hostid_entry_by_lhi(&hip_local_hostid_db, &dsa_lhi.hit));
#endif
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

	/* free the dynamically reserved memory and
	   set host_id to null to signal that it is free */
	HIP_FREE(id->host_id);
	HIP_FREE(id);
	err = 0;
	return err;
}

/**
 * hip_add_localhost_id - add a localhost id to the databases
 * @lhi: the HIT of the host
 * @host_id: the host id of the host
 *
 * Returns: zero on success, or negative error value on failure
 */
int hip_del_localhost_id(const struct hip_lhi *lhi)
{
	return hip_del_host_id(&hip_local_hostid_db, (struct hip_lhi *)lhi);
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
 * hip_get_any_localhost_host_id - Self documenting.
 *
 * NOTE: Remember to free the host id structure after use.
 *
 * Returns pointer to newly allocated area that contains a localhost
 * HI. %NULL is returned is problems are encountered. 
 */
/*struct hip_host_id *hip_get_any_localhost_host_id(int algo)
{
	struct hip_host_id *result;
	// XX TODO: use the algo
	result = hip_get_host_id_by_algo(&hip_local_hostid_db,NULL, algo);
	return result;
}*/


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

#undef HIP_READ_LOCK_DB
#undef HIP_WRITE_LOCK_DB
#undef HIP_READ_UNLOCK_DB
#undef HIP_WRITE_UNLOCK_DB
