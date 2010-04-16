/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @brief this file contains IPsec management functionality borrowed from Racoon
 */

#define _BSD_SOURCE

#include "config.h"

#include <sys/types.h>
#include <linux/ipsec.h>

#include "config.h"
#include "hipd/pfkeyapi.h"
#include "lib/ipsec/libpfkey.h"
#include "lib/ipsec/pfkeyv2.h"
#include "lib/core/hip_udp.h"
#include "lib/core/keylen.h"
#include "lib/core/debug.h"
#include "pfkeysadb.h"

/**
 * This function fills in policy0 and policylen0 according to the given parameters
 * The full implementation can be found in racoon.
 *
 * @param policy0 the IPsec policy
 * @param policylen0 length of the policy
 * @param direction IPSEC_DIR_INBOUND | IPSEC_DIR_OUTBOUND
 * @param src the source address for the policy
 * @param dst the destination address for the policy
 * @param mode the IPsec mode
 * @param cmd add or delete
 */
int getsadbpolicy(caddr_t *policy0, int *policylen0, int direction,
                  struct sockaddr *src, struct sockaddr *dst, u_int mode, int cmd)
{
    struct sadb_x_policy *xpl;
    struct sadb_x_ipsecrequest *xisr;
    caddr_t policy, p;
    int policylen;
    int xisrlen, src_len, dst_len;

    HIP_DEBUG("\n");
    /* get policy buffer size */
    policylen = sizeof(struct sadb_x_policy);
    if (cmd != SADB_X_SPDDELETE) {
        xisrlen    = sizeof(*xisr);
        xisrlen   += (sysdep_sa_len(src) + sysdep_sa_len(dst));
        policylen += PFKEY_ALIGN8(xisrlen);
    }

    /* make policy structure */
    policy = malloc(policylen);
    if (!policy) {
        HIP_ERROR("Cannot allocate memory for policy\n");
        return -ENOMEM;
    }

    xpl                        = (struct sadb_x_policy *) policy;
    xpl->sadb_x_policy_len     = PFKEY_UNIT64(policylen);
    xpl->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
    xpl->sadb_x_policy_type    = IPSEC_POLICY_IPSEC;
    xpl->sadb_x_policy_dir     = direction;
    xpl->sadb_x_policy_id      = 0;

    if (cmd == SADB_X_SPDDELETE) {
        goto end;
    }

    xisr                            = (struct sadb_x_ipsecrequest *) (xpl + 1);

    xisr->sadb_x_ipsecrequest_proto = SADB_SATYPE_ESP;
    xisr->sadb_x_ipsecrequest_mode  = mode;
    xisr->sadb_x_ipsecrequest_level = IPSEC_LEVEL_REQUIRE;
    xisr->sadb_x_ipsecrequest_reqid = 0;
    p                               = (caddr_t) (xisr + 1);

    xisrlen                         = sizeof(*xisr);

    src_len                         = sysdep_sa_len(src);
    dst_len                         = sysdep_sa_len(dst);
    xisrlen                        += src_len + dst_len;

    memcpy(p, src, src_len);
    p                              += src_len;

    memcpy(p, dst, dst_len);
    p                              += dst_len;

    xisr->sadb_x_ipsecrequest_len   = PFKEY_ALIGN8(xisrlen);
end:
    *policy0                        = policy;
    *policylen0                     = policylen;
    return 0;
}
