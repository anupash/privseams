#ifndef HIP_LHASHTABLE_H
#define HIP_LHASHTABLE_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include "debug.h"
#include "list.h"

#undef MIN_NODES
#define MIN_NODES	16
#define UP_LOAD		(2*LH_LOAD_MULT) /* load times 256  (default 2) */
#define DOWN_LOAD	(LH_LOAD_MULT)   /* load times 256  (default 1) */

#if 0
static LHASH_HIP *amih;
static LHASH_HIP *tblhash=NULL;
static uint reclength=37;
#endif

/* OpenSSL 1.0.0 introduced backwards incompatible changes to the lhash.
   These backwards compatibility hacks can be removed when all platforms
   support OpenSSL 1.0.0 by default. */
#ifndef LHASH_OF
#define LHASH_OF(type) struct lhash_st_##type
#define DECLARE_LHASH_OF(type) LHASH_OF(type) { int dummy; }

#undef IMPLEMENT_LHASH_HASH_FN
#undef IMPLEMENT_LHASH_COMP_FN
#undef IMPLEMENT_LHASH_DOALL_FN
#undef IMPLEMENT_LHASH_DOALL_ARG_FN

#define IMPLEMENT_LHASH_HASH_FN(name, o_type) \
  unsigned long name##_LHASH_HASH(const void *arg) { \
  const o_type *a = arg; \
  return name##_hash(a); }
#define IMPLEMENT_LHASH_COMP_FN(name, o_type) \
  int name##_LHASH_COMP(const void *arg1, const void *arg2) { \
  const o_type *a = arg1;             \
  const o_type *b = arg2; \
  return name##_cmp(a,b); }
#define IMPLEMENT_LHASH_DOALL_FN(name, o_type) \
  void name##_LHASH_DOALL(void *arg) { \
  o_type *a = arg; \
  name##_doall(a); }
#define IMPLEMENT_LHASH_DOALL_ARG_FN(name, o_type, a_type) \
  void name##_LHASH_DOALL_ARG(void *arg1, void *arg2) { \
  o_type *a = arg1; \
  a_type *b = arg2; \
  name##_doall_arg(a, b); }
#endif

//typedef LHASH hip_ht_common;
typedef DECLARE_LHASH_OF(HIP_HT) hip_ht_common;
typedef hip_ht_common HIP_HASHTABLE;

static inline LHASH_OF(HIP_HT) * hip_ht_init(LHASH_HASH_FN_TYPE hashfunc, LHASH_COMP_FN_TYPE cmpfunc)
{
	return (LHASH_OF(HIP_HT) *) lh_new(hashfunc, cmpfunc);
}

#define hip_ht_uninit(head) lh_free(head)

#define hip_ht_find(head, data) lh_retrieve(((LHASH_OF(HIP_HT) *)(head)), data)
static inline int hip_ht_add(hip_ht_common *head, void *data)
{
	if (lh_insert(((void *) head), data)) {
	        HIP_DEBUG("hash replace did not occur\n");
	}
	return 0;
}
#define hip_ht_delete(head, data) lh_delete(((LHASH_OF(HIP_HT) *)(head)), data)

#define HIP_LOCK_HT(hash)
#define HIP_UNLOCK_HT(hash)

#endif /* LHASHTABLE_H */

