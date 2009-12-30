#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include "debug.h"
#include "list.h"

#ifndef HIP_LHASHTABLE_H
#define HIP_LHASHTABLE_H

/* OpenSSL 1.0.0 introduced backwards incompatible changes to the lhash.
   These backwards compatibility hacks can be removed when all platforms
   support OpenSSL 1.0.0 by default. */
#ifdef LHASH_OF
#define HIPL_OPENSSL_100
#endif /* LHASH_OF */

#undef MIN_NODES
#define MIN_NODES	16

#define HIP_LOCK_HT(hash)
#define HIP_UNLOCK_HT(hash)

void hip_ht_uninit(void *head);
void *hip_ht_find(void *head, void *data);
void *hip_ht_delete(void *head, void *data);
int hip_ht_add(void *head, void *data);

#ifdef HIPL_OPENSSL_100

#define LHASH100_CAST _LHASH

typedef DECLARE_LHASH_OF(HIP_HT) hip_ht_common;
typedef hip_ht_common HIP_HASHTABLE;

LHASH_OF(HIP_HT) * hip_ht_init(LHASH_HASH_FN_TYPE hashfunc, LHASH_COMP_FN_TYPE cmpfunc);

#else

#define LHASH100_CAST void

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
typedef DECLARE_LHASH_OF(HIP_HT) hip_ht_common;
typedef LHASH HIP_HASHTABLE;

HIP_HASHTABLE * hip_ht_init(LHASH_HASH_FN_TYPE hashfunc,
			    LHASH_COMP_FN_TYPE cmpfunc);
#endif

void hip_ht_doall(void *head, LHASH_DOALL_FN_TYPE func);				 
void hip_ht_doall_arg(void *head, LHASH_DOALL_ARG_FN_TYPE func, void *arg);

#endif /* LHASHTABLE_H */

