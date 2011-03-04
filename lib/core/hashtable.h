/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef HIP_LIB_CORE_HASHTABLE_H
#define HIP_LIB_CORE_HASHTABLE_H

#include <openssl/lhash.h>

#include "list.h"

#define STATIC_IMPLEMENT_LHASH_COMP_FN      static IMPLEMENT_LHASH_COMP_FN
#define STATIC_IMPLEMENT_LHASH_DOALL_FN     static IMPLEMENT_LHASH_DOALL_FN
#define STATIC_IMPLEMENT_LHASH_DOALL_ARG_FN static IMPLEMENT_LHASH_DOALL_ARG_FN
#define STATIC_IMPLEMENT_LHASH_HASH_FN      static IMPLEMENT_LHASH_HASH_FN

/* OpenSSL 1.0.0 introduced backwards incompatible changes to the lhash.
 * These backwards compatibility hacks can be removed when all platforms
 * support OpenSSL 1.0.0 by default. */
#ifdef LHASH_OF

#define LHASH_CAST (_LHASH *)

typedef DECLARE_LHASH_OF(HIP_HT) HIP_HASHTABLE;
typedef LHASH_OF(HIP_HT)         HIP_HASHTABLE_TYPE;

#else

#define LHASH_CAST

#define LHASH_OF(type) struct lhash_st_ ## type
#define DECLARE_LHASH_OF(type) LHASH_OF(type) { int dummy; }

#undef IMPLEMENT_LHASH_HASH_FN
#undef IMPLEMENT_LHASH_COMP_FN
#undef IMPLEMENT_LHASH_DOALL_FN
#undef IMPLEMENT_LHASH_DOALL_ARG_FN

#define IMPLEMENT_LHASH_HASH_FN(name, o_type) \
    unsigned long name ## _LHASH_HASH(const void *arg) { \
        const o_type *a = arg; \
        return name ## _hash(a); }
#define IMPLEMENT_LHASH_COMP_FN(name, o_type) \
    int name ## _LHASH_COMP(const void *arg1, const void *arg2) { \
        const o_type *a = arg1;             \
        const o_type *b = arg2; \
        return name ## _cmp(a, b); }
#define IMPLEMENT_LHASH_DOALL_FN(name, o_type) \
    void name ## _LHASH_DOALL(void *arg) { \
        o_type *a = arg; \
        name ## _doall(a); }
#define IMPLEMENT_LHASH_DOALL_ARG_FN(name, o_type, a_type) \
    void name ## _LHASH_DOALL_ARG(void *arg1, void *arg2) { \
        o_type *a = arg1; \
        a_type *b = arg2; \
        name ## _doall_arg(a, b); }

typedef LHASH         HIP_HASHTABLE;
typedef HIP_HASHTABLE HIP_HASHTABLE_TYPE;

#endif

HIP_HASHTABLE_TYPE *hip_linked_list_init(void);
HIP_HASHTABLE_TYPE *hip_ht_init(LHASH_HASH_FN_TYPE hashfunc,
                                LHASH_COMP_FN_TYPE cmpfunc);
void hip_ht_uninit(void *head);
void *hip_ht_find(void *head, const void *data);
void *hip_ht_delete(void *head, void *data);
int hip_ht_add(void *head, void *data);
void hip_ht_doall(void *head, LHASH_DOALL_FN_TYPE func);
void hip_ht_doall_arg(void *head, LHASH_DOALL_ARG_FN_TYPE func,
                      void *arg);

#endif /* HIP_LIB_CORE_HASHTABLE_H */
