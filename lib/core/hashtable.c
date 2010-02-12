#include "hashtable.h"

#ifdef HIPL_OPENSSL_100

LHASH_OF(HIP_HT) * hip_ht_init(LHASH_HASH_FN_TYPE hashfunc, LHASH_COMP_FN_TYPE cmpfunc)
{
    return (LHASH_OF(HIP_HT) *)lh_new(hashfunc, cmpfunc);
}

#else /* not HIPL_OPENSSL_100 */

HIP_HASHTABLE *hip_ht_init(LHASH_HASH_FN_TYPE hashfunc,
                           LHASH_COMP_FN_TYPE cmpfunc)
{
    return (HIP_HASHTABLE *) lh_new(hashfunc, cmpfunc);
}

#endif /* HIPL_OPENSSL_100 */

void hip_ht_uninit(void *head)
{
    lh_free(head);
}

void *hip_ht_find(void *head, void *data)
{
    return lh_retrieve((LHASH100_CAST *) head, data);
}

int hip_ht_add(void *head, void *data)
{
    if (lh_insert((LHASH100_CAST *) head, data)) {
        HIP_DEBUG("hash replace did not occur\n");
    }
    return 0;
}

void *hip_ht_delete(void *head, void *data)
{
    return lh_delete((LHASH100_CAST *) head, data);
}

void hip_ht_doall(void *head, LHASH_DOALL_FN_TYPE func)
{
    lh_doall((LHASH100_CAST *) head, func);
}

void hip_ht_doall_arg(void *head, LHASH_DOALL_ARG_FN_TYPE func, void *arg)
{
    lh_doall_arg((LHASH100_CAST *) head, func, arg);
}
