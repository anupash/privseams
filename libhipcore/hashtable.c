#include "hashtable.h"

#ifdef HIPL_OPENSSL_100

LHASH_OF(HIP_HT) * hip_ht_init(LHASH_HASH_FN_TYPE hashfunc, LHASH_COMP_FN_TYPE cmpfunc)
{
	return (LHASH_OF(HIP_HT) *) lh_new(hashfunc, cmpfunc);
}

void hip_ht_uninit(void *head)
{
	lh_free(head);
}

void *hip_ht_find(void *head, void *data)
{
	return lh_retrieve((_LHASH *)head, data);
}

int hip_ht_add(hip_ht_common *head, void *data)
{
	if (lh_insert(((_LHASH *) head), data)) {
		HIP_DEBUG("hash replace did not occur\n");
	}
	return 0;
}

void *hip_ht_delete(hip_ht_common *head, void *data)
{
	return lh_delete(((_LHASH *) head), data);
}

#else /* not HIPL_OPENSSL_100 */

#endif /* HIPL_OPENSSL_100 */


