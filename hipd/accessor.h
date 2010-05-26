/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_HIPD_ACCESSOR_H
#define HIP_HIPD_ACCESSOR_H

#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/des.h>
#include <sys/time.h>

#include "config.h"
#include "lib/core/hashtable.h"

/** @defgroup daemon_states HIP daemon states
 * @{
 */
/** Low mask for daemon states. */
#define HIPD_STATE_MASK         0xff
/** Daemon is ok and executing. */
#define HIPD_STATE_EXEC         0x00
/** Daemon is closing. */
#define HIPD_STATE_CLOSING      0x01
/** Daemon is closed, exiting main(). */
#define HIPD_STATE_CLOSED       0x02

/** Daemon is restarting. */
#define HIPD_FLAG_RESTART       0x00000100
/* @} */

#define INDEX_HASH_LENGTH       SHA_DIGEST_LENGTH

#define INDEX_HASH_FN           HIP_DIGEST_SHA1

/** Specifies the NAT status of the daemon. This value indicates if the current
 *  machine is behind a NAT. Defined in hipd.c */
extern int hipproxy;

unsigned int hipd_get_state(void);
void hipd_set_state(unsigned int);
int hipd_get_flag(unsigned int);
void hipd_set_flag(unsigned int);

#endif /* HIP_HIPD_ACCESSOR_H */

