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

/**
 * @file
 * This file defines building and parsing functions for Host Identity
 * Protocol (HIP) kernel module and user messages. The functions can
 * be used for sending on-the-wire HIP control messages to the
 * network.  Also, the hip_common structure is overloaded to
 * accommodate inteprocess communications between hipd, hipfw and
 * hipconf. This avoids the maintenance overhead of a second parser.
 *
 * Keep in mind the following things when using the builder:
 * <ul>
 * <li>Never access members of @c hip_common and @c hip_tlv_common directly. Use
 * the accessor functions to hide byte ordering and length manipulation.</li>
 * <li>Remember always to use <code>__attribute__ ((packed))</code> (see hip.h)
 * with builder because compiler adds padding into the structures.</li>
 * <li>This file is shared between userspace and kernel: do not put any memory
 * allocations or other kernel/userspace specific stuff into here.</li>
 * <li>If you build more functions like build_signature2_contents(), remember
 * to use hip_build_generic_param() in them.</li>
 * </ul>
 *
 * Usage examples:
 * <ul>
 * <li>sender of "add mapping", i.e. the hip module in kernel</li>
 * <ul>
 * <li>struct hip_common *msg = malloc(HIP_MAX_PACKET);</li>
 * <li>hip_msg_init(msg);</li>
 * <li>err = hip_build_user_hdr(msg, HIP_MSG_ADD_MAP_HIT_IP, 0);</li>
 * <li>err = hip_build_param_contents(msg, &hit, HIP_PARAM_HIT,
 * sizeof(struct in6_addr));</li>
 * <li>err = hip_build_param_contents(msg, &ip, HIP_PARAM_IPV6_ADDR,
 * sizeof(struct in6_addr));</li>
 * <li>send the message to user space.</li>
 * </ul>
 * <li>receiver of "add mapping", i.e. the daemon</li>
 * <ul>
 * <li>struct hip_common *msg = malloc(HIP_MAX_PACKET);</li>
 * <li>receive the message from kernel.</li>
 * <li>if (msg->err) goto_error_handler;</li>
 * <li>hit = hip_get_param_contents(msg, HIP_PARAM_HIT);</li>
 * <li>note: hit can be null, if the param was not found.</li>
 * </li>
 * <li>note: hit can be null.</li>
 * </ul>
 * </ul>
 *
 * @brief Serialization of HIP-related data structures to HIP control
 *        messages. The functionality is overloaded to support also
 *        interprocess communications between hipd, hipfw and hipconf.
 * @author Miika Komu
 * @author Mika Kousa
 * @author Tobias Heer
 *
 * @see @c message.c contains functions to read and write HIP-related messages
 * @note   In network packets @c hip_build_network_hdr() should be used instead
 *         of @c hip_build_user_hdr().
 * @todo Macros for doing @c ntohs() and @c htons() conversion? Currently they are
 * used in a platform dependent way.
 * @todo Why does build network header return void whereas build daemon does
 *       not?
 * @todo There is a small TODO list in @c hip_build_network_hdr()
 * @todo <span style="color:#f00">Update the comments of this file.</span>
 */

#define _BSD_SOURCE

#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/md5.h>

#include "lib/core/common.h"
#include "lib/core/prefix.h"
#include "lib/tool/checksum.h"
#include "config.h"
#include "builder.h"
#include "crypto.h"
#include "hostid.h"


/* ARRAY_SIZE is defined in linux/kernel.h, but it is in #ifdef __KERNEL__ */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif /* ARRAY_SIZE */

enum select_dh_key_t { STRONGER_KEY, WEAKER_KEY };

static enum select_dh_key_t select_dh_key = STRONGER_KEY;

/**
 * attach a HIP RR and a hostname into a hip_host_id_priv parameter
 *
 * @param host_id a hip_host_id_priv parameter
 * @param rr_data a HIP resource record structure to be copied
 * @param fqdn a string containing a hostname
 *
 * @see hip_build_endpoint_hdr()
 */
static void hip_build_param_host_id_only_priv(struct hip_host_id_priv *host_id,
                                              const void *rr_data,
                                              const char *fqdn)
{
    unsigned int rr_len = ntohs(host_id->hi_length) -
                          sizeof(struct hip_host_id_key_rdata);
    uint16_t fqdn_len;

    memcpy(host_id->key, rr_data, rr_len);

    fqdn_len = ntohs(host_id->di_type_length) & 0x0FFF;
    if (fqdn_len) {
        memcpy(host_id->hostname, fqdn, fqdn_len);
    }
}

/**
 * Fill in an endpoint structure that can contain a DSA or RSA key in HIP
 * RR format. This is used for sending new private keys to hipd
 * using hipconf.
 *
 * @param endpoint The output argument where the result will be written.
 *                 Caller is responsible of reserving enough memory.
 * @param endpoint_hdr should be filled with hip_build_endpoint_hdr()
 * @param hostname a string containing the hostname (or URI/NAI) for the endpoint
 * @param key_rr DNS resource record for HIP (contains the public or private key)
 * @note endpoint is not padded because it for internal messaging only
 */
static void hip_build_endpoint(struct endpoint_hip *endpoint,
                               const struct endpoint_hip *endpoint_hdr,
                               const char *hostname,
                               const unsigned char *key_rr)
{
    HIP_ASSERT(endpoint_hdr->length == sizeof(struct endpoint_hip) +
               hip_get_param_total_len(&endpoint_hdr->id.host_id) -
               sizeof(struct hip_host_id_priv));
    memcpy(endpoint, endpoint_hdr, sizeof(struct endpoint_hip));
    hip_build_param_host_id_only_priv(&endpoint->id.host_id, key_rr, hostname);
}

/**
 * Initialize a message to be sent to the daemon or into the network.
 * Initialization must be done before any parameters are build into
 * the message. Otherwise the writing of the parameters will result in undefined
 * behaviour.
 *
 * @param msg the message to be initialized
 */
void hip_msg_init(struct hip_common *msg)
{
    /* note: this is used both for daemon and network messages */
    memset(msg, 0, HIP_MAX_PACKET);
}

/**
 * Allocate and initialize a HIP packet
 *
 * Return: initialized HIP packet if successful, NULL on error.
 */
struct hip_common *hip_msg_alloc(void)
{
    struct hip_common *ptr;

    ptr = malloc(HIP_MAX_PACKET);
    if (ptr) {
        hip_msg_init(ptr);
    }
    return ptr;
}

/**
 * convert on-the-wire message length total length to bytes
 *
 * @param len the length of the HIP header as it is in the header
 *       (in host byte order)
 * @return the real size of HIP header in bytes (host byte order)
 * @note compared to hip_convert_msg_total_len_to_bytes_16(), this
 *       function inputs an 8-bit integer
 */
static uint16_t hip_convert_msg_total_len_to_bytes(const hip_hdr_len_t len)
{
    return (len == 0) ? 0 : ((len + 1) << 3);
}

/**
 * convert a interprocess message total length to bytes
 *
 * @param len the length of the HIP header as it is in the header
 *       (in host byte order)
 * @return the real size of HIP header in bytes (host byte order)
 * @note compared to hip_convert_msg_total_len_to_bytes(), this
 *       function inputs a 16-bit integer
 */
static uint16_t hip_convert_msg_total_len_to_bytes_16(uint16_t len)
{
    return (len == 0) ? 0 : ((len + 1) << 3);
}

/**
 * get the total size of the header in bytes
 *
 * @param msg pointer to the beginning of the message header
 * @return the total size of the message in bytes (host byte order).
 */
uint16_t hip_get_msg_total_len(const struct hip_common *msg)
{
    if (msg->ver_res == HIP_USER_VER_RES) {
        const struct hip_common_user *umsg = (const struct hip_common_user *) msg;
        return hip_convert_msg_total_len_to_bytes_16(umsg->len);
    } else {
        return hip_convert_msg_total_len_to_bytes(msg->payload_len);
    }
}

/**
 * set the total message length in bytes
 *
 * @param msg pointer to the beginning of the message header
 * @param len the total size of the message in bytes (host byte order)
 */
void hip_set_msg_total_len(struct hip_common *msg, uint16_t len)
{
    /* assert len % 8 == 0 ? */
    if (msg->ver_res == HIP_USER_VER_RES && len < HIP_MAX_PACKET) {
        struct hip_common_user *umsg = (struct hip_common_user *) msg;
        umsg->len = (len < 8) ? 0 : ((len >> 3) - 1);
    } else {
        msg->payload_len = (len < 8) ? 0 : ((len >> 3) - 1);
    }
}

/**
 * get the type of the message in host byte order
 *
 * @param msg pointer to the beginning of the message header
 * @return the type of the message (in host byte order)
 *
 */
hip_hdr_type_t hip_get_msg_type(const struct hip_common *msg)
{
    return msg->type_hdr;
}

/**
 * set the type of the message
 *
 * @param msg pointer to the beginning of the message header
 * @param type the type of the message (in host byte order)
 */
static void hip_set_msg_type(struct hip_common *msg, hip_hdr_type_t type)
{
    msg->type_hdr = type;
}

/**
 * get the error values from daemon message header
 * @param msg pointer to the beginning of the message header
 *
 * @return the error value from the message (in host byte order)
 */
hip_hdr_err_t hip_get_msg_err(const struct hip_common *msg)
{
    /* Note: error value is stored in checksum field for daemon messages.
     * This should be fixed later on by defining an own header for
     * daemon messages. This function should then input void* as
     * the message argument and cast it to the daemon message header
     * structure. */
    return msg->checksum;     /* 1 byte, no ntohs() */
}

/**
 * set the error value of the daemon message
 *
 * @param msg pointer to the beginning of the message header
 * @param err the error value
 */
void hip_set_msg_err(struct hip_common *msg, hip_hdr_err_t err)
{
    /* note: error value is stored in checksum field for daemon messages */
    msg->checksum = err;
}

/**
 * retrieve message checksum
 *
 * @param msg the message
 * @return the checksum
 */
uint16_t hip_get_msg_checksum(struct hip_common *msg)
{
    return msg->checksum;  /* one byte, no ntohs() */
}

/**
 * zero message checksum
 *
 * @param msg the message
 */
void hip_zero_msg_checksum(struct hip_common *msg)
{
    msg->checksum = 0;     /* one byte, no ntohs() */
}

/**
 * set message checksum
 *
 * @param msg the message
 * @param checksum the checksum value
 */
void hip_set_msg_checksum(struct hip_common *msg, uint8_t checksum)
{
    msg->checksum = checksum;     /* one byte, no ntohs() */
}

/**
 * get the total size of a message parameter
 *
 * @param tlv_common pointer to the parameter
 * @return the total length of the parameter in bytes (host byte
 * order), including the padding
 */
hip_tlv_len_t hip_get_param_total_len(const void *tlv_common)
{
    return HIP_LEN_PAD(sizeof(struct hip_tlv_common) +
                       ntohs(((const struct hip_tlv_common *)
                              tlv_common)->length));
}

/**
 * get the size of the parameter contents
 *
 * @param tlv_common pointer to the parameter
 * @return the length of the parameter in bytes (in host byte order),
 *          excluding padding and the length of "type" and "length" fields
 */
hip_tlv_len_t hip_get_param_contents_len(const void *tlv_common)
{
    return ntohs(((const struct hip_tlv_common *) tlv_common)->length);
}

/**
 * set parameter length into the header of the message
 *
 * @param tlv_generic pointer to the parameter
 * @param len the length of the parameter in bytes (in host byte order),
 *              excluding padding and the length of "type" and "length" fields
 */
void hip_set_param_contents_len(struct hip_tlv_common *tlv_generic,
                                hip_tlv_len_t len)
{
    tlv_generic->length = htons(len);
}

/**
 * retrieve the type of a HIP parameter
 *
 * @param tlv_common pointer to the parameter
 * @return the type of the parameter (in host byte order)
 */
hip_tlv_type_t hip_get_param_type(const void *tlv_common)
{
    return ntohs(((const struct hip_tlv_common *) tlv_common)->type);
}

/**
 * set parameter type
 *
 * @param tlv_generic pointer to the parameter
 * @param type type of the parameter (in host byte order)
 */
void hip_set_param_type(struct hip_tlv_common *tlv_generic, hip_tlv_type_t type)
{
    tlv_generic->type = htons(type);
}

/**
 * get the total length of a Diffie-Hellman parameter
 *
 * @param dh pointer to the Diffie-Hellman parameter
 * @return the length of the public value Diffie-Hellman parameter in bytes
 *          (in host byte order).
 */
static hip_tlv_len_t hip_get_diffie_hellman_param_public_value_len(const struct hip_diffie_hellman *dh)
{
    return hip_get_param_contents_len(dh) - sizeof(uint8_t) - sizeof(uint16_t);
}

/**
 * select the strongest DH key according RFC5201, section 5.2.6:
 *
 *  The sender can include at most two different Diffie-Hellman public
 *  values in the DIFFIE_HELLMAN parameter.  This gives the possibility
 *  e.g. for a server to provide a weaker encryption possibility for a
 *  PDA host that is not powerful enough.  It is RECOMMENDED that the
 *  Initiator, receiving more than one public values selects the stronger
 *  one, if it supports it.
 *
 * @param dhf pointer to the Diffie-Hellman parameter with two DH keys.
 * @return a pointer to the chosen Diffie-Hellman parameter
 */
struct hip_dh_public_value *hip_dh_select_key(struct hip_diffie_hellman *dhf)
{
    struct hip_dh_public_value *dhpv1 = NULL, *dhpv2 = NULL, *err = NULL;

    if (ntohs(dhf->pub_val.pub_len) ==
        hip_get_diffie_hellman_param_public_value_len(dhf)) {
        HIP_DEBUG("Single DHF public value received\n");
        return (struct hip_dh_public_value *) &dhf->pub_val.group_id;
    } else {
        dhpv1 = (struct hip_dh_public_value *) &dhf->pub_val.group_id;
        dhpv2 = (struct hip_dh_public_value *)
                (dhf->pub_val.public_value + ntohs(dhf->pub_val.pub_len));

        HIP_IFEL(hip_get_diffie_hellman_param_public_value_len(dhf) !=
                 ntohs(dhpv1->pub_len) + sizeof(uint8_t) + sizeof(uint16_t)
                 + ntohs(dhpv2->pub_len), dhpv1, "Malformed DHF parameter\n");

        HIP_DEBUG("Multiple DHF public values received\n");

        /* Selection of a DH key depending on select_dh_key */
        if ((select_dh_key == STRONGER_KEY &&
             dhpv1->group_id >= dhpv2->group_id) ||
            (select_dh_key == WEAKER_KEY &&
             dhpv1->group_id <= dhpv2->group_id)) {
            return dhpv1;
        } else {
            return dhpv2;
        }
    }
out_err:
    return err;
}

/**
 * retrive host id public key algorithm
 *
 * @param host_id a hip_host_id parameter
 * @return the host id public key algorithm
 */
uint8_t hip_get_host_id_algo(const struct hip_host_id *host_id)
{
    return host_id->rdata.algorithm;     /* 8 bits, no ntons() */
}

/**
 * Translate a service life time from seconds to a 8-bit integer value. The
 * lifetime value in seconds is translated to a 8-bit integer value using
 * following formula: <code>lifetime = (8 * (log(seconds) / log(2)))
 * + 64</code> and truncated. The formula is the inverse of the formula given
 * in the registration draft.
 *
 * @param  seconds  the lifetime to convert.
 * @param  lifetime a target buffer for the coverted lifetime.
 * @return          zero on success, -1 on error. Error occurs when @c seconds
 *                  is zero or greater than 15384774.
 */
int hip_get_lifetime_value(time_t seconds, uint8_t *lifetime)
{
    /* Check that we get a lifetime value between 1 and 255. The minimum
     * lifetime according to the registration draft is 0.004 seconds, but
     * the reverse formula gives zero for that. 15384774.906 seconds is the
     * maximum value. The boundary checks done here are just curiosities
     * since services are usually granted for minutes to a couple of days,
     * but not for milliseconds and days. However, log() gives a range error
     * if "seconds" is zero. */
    if (seconds == 0) {
        *lifetime = 0;
        return -1;
    } else if (seconds > 15384774)   {
        *lifetime = 255;
        return -1;
    } else {
        *lifetime = (8 * (log(seconds) / log(2))) + 64;
        return 0;
    }
}

/**
 * Translate a service life time from a 8-bit integer value to seconds. The
 * lifetime value is translated to a 8-bit integer value using following
 * formula: <code>seconds = 2^((lifetime - 64)/8)</code>.
 *
 * @param  lifetime the lifetime to convert.
 * @param  seconds  a target buffer for the converted lifetime.
 * @return          zero on success, -1 on error. Error occurs when @c lifetime
 *                  is zero.
 */
int hip_get_lifetime_seconds(uint8_t lifetime, time_t *seconds)
{
    if (lifetime == 0) {
        *seconds = 0;
        return -1;
    }
    /* All values between from 1 to 63 give just fractions of a second. */
    else if (lifetime < 64) {
        *seconds = 1;
        return 0;
    } else {
        *seconds = pow(2, ((double) ((lifetime) - 64) / 8));
        return 0;
    }
}

/**
 * check the validity of user (interprocess) message length
 *
 * @param msg pointer to the message
 * @return 1 if the message length is valid, or 0 if the message length is
 *          invalid
 */
static int hip_check_user_msg_len(const struct hip_common *msg)
{
    uint16_t len;

    HIP_ASSERT(msg);
    len = hip_get_msg_total_len(msg);

    if (len < sizeof(struct hip_common) || len > HIP_MAX_PACKET) {
        return 0;
    } else {
        return 1;
    }
}

/**
 * check the validity of a network (on-the-wire) message length
 *
 * @param msg pointer to the message
 * @return 1 if the message length is valid, or 0 if the message length is
 *          invalid
 */
int hip_check_network_msg_len(const struct hip_common *msg)
{
    uint16_t len;

    HIP_ASSERT(msg);
    len = hip_get_msg_total_len(msg);

    if (len < sizeof(struct hip_common) || len > HIP_MAX_NETWORK_PACKET) {
        return 0;
    } else {
        return 1;
    }
}

/**
 * Check the type of the network message
 *
 * @param msg pointer to the message
 * @return 1 if the message type is valid, or 0 if the message type is
 *          invalid
 */
static int hip_check_network_msg_type(const struct hip_common *msg)
{
    int ok                     = 0;
    hip_hdr_type_t supported[] =
    {
        HIP_I1,
        HIP_R1,
        HIP_I2,
        HIP_R2,
        HIP_UPDATE,
        HIP_NOTIFY,
        HIP_CLOSE,
        HIP_CLOSE_ACK,
        HIP_LUPDATE
    };
    hip_hdr_type_t i;
    hip_hdr_type_t type = hip_get_msg_type(msg);

    for (i = 0; i < sizeof(supported) / sizeof(hip_hdr_type_t); i++) {
        if (type == supported[i]) {
            ok = 1;
            break;
        }
    }

    return ok;
}

/**
 * hip_check_userspace_param_type - check the userspace parameter type
 * @param param pointer to the parameter
 *
 * @return 1 if parameter type is valid, or 0 if parameter type is invalid
 */
static int hip_check_userspace_param_type(UNUSED const struct hip_tlv_common *param)
{
    return 1;
}

/**
 * Check the network (on-the-wire) parameter type.
 *
 * Optional parameters are not checked, because the code just does not
 * use them if they are not supported.
 *
 * @param param the network parameter
 * @return 1 if parameter type is valid, or 0 if parameter type
 * is not valid. "Valid" means all optional and non-optional parameters
 * in the HIP draft.
 * @todo Clarify the functionality and explanation of this function. Should
 *       new parameters be added to the checked parameters list as they are
 *       introduced in extensions drafts (RVS, NAT, Registration...), or should
 *       here only be the parameters listed in Sections 5.2.3 through Section
 *       5.2.18 of the draft-ietf-hip-base-06?
 */
static int hip_check_network_param_type(const struct hip_tlv_common *param)
{
    int ok                 = 0;
    hip_tlv_type_t i;
    hip_tlv_type_t valid[] =
    {
        HIP_PARAM_ACK,
        HIP_PARAM_CERT,
        HIP_PARAM_DIFFIE_HELLMAN,
        HIP_PARAM_ECHO_REQUEST,
        HIP_PARAM_ECHO_REQUEST_SIGN,
        HIP_PARAM_ECHO_RESPONSE,
        HIP_PARAM_ECHO_RESPONSE_SIGN,
        HIP_PARAM_ENCRYPTED,
        HIP_PARAM_ESP_INFO,
        HIP_PARAM_ESP_INFO,
        HIP_PARAM_ESP_TRANSFORM,
        HIP_PARAM_FROM,
        HIP_PARAM_RELAY_FROM,
        //add by santtu
        HIP_PARAM_RELAY_HMAC,
        //end add
        HIP_PARAM_HIP_SIGNATURE,
        HIP_PARAM_HIP_SIGNATURE2,
        HIP_PARAM_HIP_TRANSFORM,
        HIP_PARAM_HMAC,
        HIP_PARAM_HMAC,
        HIP_PARAM_HMAC2,
        HIP_PARAM_RVS_HMAC,
        HIP_PARAM_HOST_ID,
        HIP_PARAM_LOCATOR,
        //add by santtu
        HIP_PARAM_NAT_TRANSFORM,
        HIP_PARAM_NAT_PACING,
        HIP_PARAM_STUN,
        //end add
        HIP_PARAM_NOTIFICATION,
        HIP_PARAM_PUZZLE,
        HIP_PARAM_R1_COUNTER,
        HIP_PARAM_REG_FAILED,
        HIP_PARAM_REG_INFO,
        HIP_PARAM_REG_REQUEST,
        HIP_PARAM_REG_RESPONSE,
        HIP_PARAM_SEQ,
        HIP_PARAM_SOLUTION,
        HIP_PARAM_VIA_RVS,
        HIP_PARAM_RELAY_TO,
        //add by santtu
        HIP_PARAM_REG_FROM,
        //end add
        HIP_PARAM_ESP_PROT_TRANSFORMS,
        HIP_PARAM_ESP_PROT_ANCHOR,
        HIP_PARAM_ESP_PROT_BRANCH,
        HIP_PARAM_ESP_PROT_SECRET,
        HIP_PARAM_ESP_PROT_ROOT
#ifdef CONFIG_HIP_MIDAUTH
        ,
        HIP_PARAM_ECHO_REQUEST_M,
        HIP_PARAM_ECHO_RESPONSE_M,
        HIP_PARAM_CHALLENGE_REQUEST,
        HIP_PARAM_CHALLENGE_RESPONSE
#endif /* CONFIG_HIP_MIDAUTH */
    };
    hip_tlv_type_t type = hip_get_param_type(param);

    /** @todo check the lengths of the parameters */

    for (i = 0; i < ARRAY_SIZE(valid); i++) {
        if (!(type & 0x0001)) {
            ok = 1;
            break;
        } else if (type == valid[i]) {
            ok = 1;
            break;
        }
    }

    return ok;
}

/**
 * Check the validity of parameter contents length.
 *
 * @param msg   a pointer to the beginning of the message
 * @param param a pointer to the parameter to be checked for contents length
 * @return      1 if the length of the parameter contents length was valid
 *              (the length was not too small or too large to fit into the
 *              message). Zero is returned on invalid contents length.
 * @note The msg is passed also in to check to the parameter will not cause buffer
 * overflows.
 */
static int hip_check_param_contents_len(const struct hip_common *msg,
                                        const struct hip_tlv_common *param)
{
    int ok        = 0;
    /* length in bytes */
    int param_len = hip_get_param_total_len(param);

    /* cast pointers to a compatible type for comparison below */
    const uint8_t *msg_pos    = (const uint8_t *) msg;
    const uint8_t *param_pos  = (const uint8_t *) param;

    /* Note: the lower limit is not checked, because there really is no
     * lower limit. */

    if (param_pos == msg_pos) {
        HIP_ERROR("not a parameter\n");
    } else if (param_pos + param_len > msg_pos + HIP_MAX_PACKET) {
        HIP_DEBUG("param far too long (%d)\n", param_len);
    } else if (param_len > hip_get_msg_total_len(msg)) {
        HIP_DEBUG("param too long (%d) msg_len %d\n", param_len,
                  hip_get_msg_total_len(msg));
    } else {
        ok = 1;
    }
    return ok;
}

/**
 * Iterate to the next parameter in the message
 *
 * @param msg           a pointer to the beginning of the message header
 * @param current_param a pointer to the current parameter, or NULL if the msg
 *                      is to be searched from the beginning.
 * @return              the next parameter after the current_param in @c msg, or
 *                      NULL if no parameters were found.
 */
const struct hip_tlv_common *hip_get_next_param(const struct hip_common *msg,
                                                const struct hip_tlv_common *current_param)
{
    const struct hip_tlv_common *next_param = NULL;
    const uint8_t *pos                      = (const uint8_t *) current_param;

    if (!msg) {
        HIP_ERROR("msg null\n");
        goto out;
    }

    if (current_param == NULL) {
        pos = (const uint8_t *) msg;
    }

    if (pos == (const uint8_t *) msg) {
        pos += sizeof(struct hip_common);
    } else {
        pos += hip_get_param_total_len(current_param);
    }

    next_param = (const struct hip_tlv_common *) pos;

    /* check that the next parameter does not point
     * a) outside of the message
     * b) out of the buffer with check_param_contents_len()
     * c) to an empty slot in the message */
    if (((const char *) next_param) - ((const char *) msg) >=
        hip_get_msg_total_len(msg) ||     /* a */
        !hip_check_param_contents_len(msg, next_param) ||     /* b */
        hip_get_param_contents_len(next_param) == 0) {        /* c */
        next_param = NULL;
    }

out:
    return next_param;
}

/**
 * Iterate to the next parameter in the message
 *
 * @param msg           a pointer to the beginning of the message header
 * @param current_param a pointer to the current parameter, or NULL if the msg
 *                      is to be searched from the beginning.
 * @return              the next parameter after the current_param in @c msg, or
 *                      NULL if no parameters were found.
 */
struct hip_tlv_common *hip_get_next_param_readwrite(struct hip_common *msg,
                                                    struct hip_tlv_common *current_param)
{
    struct hip_tlv_common *next_param = NULL;
    uint8_t *pos                      = (uint8_t *) current_param;

    if (!msg) {
        HIP_ERROR("msg null\n");
        goto out;
    }

    if (current_param == NULL) {
        pos = (uint8_t *) msg;
    }

    if (pos == (void *) msg) {
        pos += sizeof(struct hip_common);
    } else {
        pos += hip_get_param_total_len(current_param);
    }

    next_param = (struct hip_tlv_common *) pos;

    /* check that the next parameter does not point
     * a) outside of the message
     * b) out of the buffer with check_param_contents_len()
     * c) to an empty slot in the message */
    if (((char *) next_param) - ((char *) msg) >=
        hip_get_msg_total_len(msg) ||     /* a */
        !hip_check_param_contents_len(msg, next_param) ||     /* b */
        hip_get_param_contents_len(next_param) == 0) {        /* c */
        next_param = NULL;
    }

out:
    return next_param;
}

/**
 * Get the first parameter of the given type. If there are multiple
 * parameters of the same type, one should use hip_get_next_param()
 * after calling this function to iterate through them all.
 *
 * @param msg        a pointer to the beginning of the message header.
 * @param param_type the type of the parameter to be searched from msg
 *                   (in host byte order)
 * @return           a pointer to the first parameter of the type param_type,
 *                   or NULL if no parameters of the type param_type were not
 *                   found.
 */
const void *hip_get_param(const struct hip_common *msg,
                          hip_tlv_type_t param_type)
{
    const void *matched                        = NULL;
    const struct hip_tlv_common *current_param = NULL;

    /** @todo Optimize: stop when next parameter's type is greater than the
     *  searched one. */

    while ((current_param = hip_get_next_param(msg, current_param))) {
        if (hip_get_param_type(current_param) == param_type) {
            matched = current_param;
            break;
        }
    }

    return matched;
}

/**
 * Get the first parameter of the given type. If there are multiple
 * parameters of the same type, one should use hip_get_next_param()
 * after calling this function to iterate through them all.
 *
 * @param msg        a pointer to the beginning of the message header.
 * @param param_type the type of the parameter to be searched from msg
 *                   (in host byte order)
 * @return           a pointer to the first parameter of the type param_type,
 *                   or NULL if no parameters of the type param_type were not
 *                   found.
 */
void *hip_get_param_readwrite(struct hip_common *msg,
                              hip_tlv_type_t param_type)
{
    void *matched                        = NULL;
    struct hip_tlv_common *current_param = NULL;

    /** @todo Optimize: stop when next parameter's type is greater than the
     *  searched one. */

    while ((current_param = hip_get_next_param_readwrite(msg, current_param))) {
        if (hip_get_param_type(current_param) == param_type) {
            matched = current_param;
            break;
        }
    }

    return matched;
}

/**
 * Get contents of the first parameter of the given type. If there are multiple
 * parameters of the same type, one should use @c hip_get_next_param() after
 * calling this function to iterate through them all.
 *
 * @param msg         a pointer to the beginning of the message header
 * @param param_type the type of the parameter to be searched from msg
 *                   (in host byte order)
 * @return           a pointer to the contents of the first parameter of the
 *                   type @c param_type, or NULL if no parameters of type
 *                   @c param_type were found.
 */
const void *hip_get_param_contents(const struct hip_common *msg,
                                   hip_tlv_type_t param_type)
{
    const uint8_t *contents = hip_get_param(msg, param_type);
    if (contents) {
        contents += sizeof(struct hip_tlv_common);
    }
    return contents;
}

/**
 * hip_get_param_contents_direct - get parameter contents direct from TLV
 *
 * @param tlv_common pointer to a parameter
 * @return pointer to the contents of the tlv_common (just after the
 *          the type and length fields)
 */
void *hip_get_param_contents_direct_readwrite(void *tlv_common)
{
    return ((uint8_t *) tlv_common) + sizeof(struct hip_tlv_common);
}

/**
 * hip_get_param_contents_direct - get parameter contents direct from TLV
 *
 * @param tlv_common pointer to a parameter
 * @return pointer to the contents of the tlv_common (just after the
 *          the type and length fields)
 */
const void *hip_get_param_contents_direct(const void *tlv_common)
{
    return ((const uint8_t *) tlv_common) + sizeof(struct hip_tlv_common);
}

/**
 * @brief Find the first free parameter position in a message
 *
 * This function does not check whether the new parameter to be appended
 * would overflow the @c msg buffer. It is the responsibilty of the caller
 * to check such circumstances because this function does not know
 * the length of the object to be appended in the message. Still, this
 * function checks the special situation where the buffer is completely
 * full and returns NULL in such a case.
 *
 * @param msg a pointer to the beginning of the message header
 * @return    a pointer to the first free (padded) position, or NULL if
 *            the message was completely full
 * @todo      Should this function should return hip_tlv_common?
 */
static void *hip_find_free_param(struct hip_common *msg)
{
    struct hip_tlv_common *current_param = NULL;
    struct hip_tlv_common *last_used_pos = NULL;
    void *free_pos                       = NULL;
    uint8_t *first_pos                   = ((uint8_t *) msg) + sizeof(struct hip_common);

    /* Check for no parameters: this has to be checked separately because
     * we cannot tell from the return value of get_next_param() whether
     * the message was completely full or there just were no parameters.
     * The length is used for checking the existance of parameter, because
     * type field may be zero (SPI_LSI = 0) and therefore it cannot be
     * used for checking the existance. */
    if (hip_get_param_contents_len((struct hip_tlv_common *) first_pos)
        == 0) {
        free_pos = first_pos;
        goto out;
    }

    while ((current_param = hip_get_next_param_readwrite(msg, current_param))) {
        last_used_pos = current_param;
    }

    if (last_used_pos == NULL) {
        free_pos = NULL;         /* the message was full */
    } else {
        free_pos = ((uint8_t *) last_used_pos) +
                   hip_get_param_total_len(last_used_pos);
    }

out:
    return free_pos;
}

/**
 * @brief Update messsage header length
 *
 * This function is called always when a parameter has been added or the
 * daemon/network header was written. This function writes the new
 * header length directly into the message.
 *
 * @param msg a pointer to the beginning of the message header
 */
void hip_calc_hdr_len(struct hip_common *msg)
{
    struct hip_tlv_common *param = NULL;
    uint8_t *pos                 = (uint8_t *) msg;

    /* We cannot call get_next() or get_free() because they need a valid
     * header length which is to be (possibly) calculated now. So, the
     * header length must be calculated manually here. */

    if (hip_get_msg_total_len(msg) == 0) {
        /* msg len is zero when
         * 1) calling build_param() for the first time
         * 2) calling just the build_hdr() without building
         *    any parameters, e.g. in plain error messages */
        hip_set_msg_total_len(msg, sizeof(struct hip_common));
    } else {
        /* 3) do nothing, build_param()+ */
        /* 4) do nothing, build_param()+ and build_hdr() */
    }

    pos  += hip_get_msg_total_len(msg);
    param = (struct hip_tlv_common *) pos;
    if (hip_get_param_contents_len(param) != 0) {
        /* Case 1 and 3: a new parameter (with a valid length) has
        *  been added and the message length has not been updated. */
        hip_set_msg_total_len(msg, hip_get_msg_total_len(msg) +
                              hip_get_param_total_len(param));
        /* XX assert: new pos must be of type 0 (assume only one
         * header has been added) */
    } else {
        /* case 2 and 4: the message length does not need to be
         * updated */
    }
}

/**
 * Calculate and write the length of any HIP packet parameter
 *
 * This function can be used for semi-automatic calculation of parameter
 * length field. This function should always be used instead of manual
 * calculation of parameter lengths. The tlv_size is usually just
 * sizeof(struct hip_tlv_common), but it can include other fields than
 * just the type and length. For example, DIFFIE_HELLMAN parameter includes
 * the group field as in hip_build_param_diffie_hellman_contents().
 *
 * @param tlv_common pointer to the beginning of the parameter
 * @param tlv_size size of the TLV header  (in host byte order)
 * @param contents_size size of the contents after the TLV header
 *                 (in host byte order)
 */
void hip_calc_generic_param_len(struct hip_tlv_common *tlv_common,
                                hip_tlv_len_t tlv_size,
                                hip_tlv_len_t contents_size)
{
    hip_set_param_contents_len(tlv_common,
                               tlv_size + contents_size -
                               sizeof(struct hip_tlv_common));
}

/**
 * Calculate the length of a "normal" TLV structure.
 * This function calculates and writes the length of TLV structure field.
 * This function is different from hip_calc_generic_param_len() because
 * it assumes that the length of the header of the TLV is just
 * sizeof(struct hip_tlv_common).
 *
 * @param tlv_common pointer to the beginning of the TLV structure
 * @param contents_size size of the contents after type and length fields
 *                 (in host byte order)
 */
void hip_calc_param_len(struct hip_tlv_common *tlv_common,
                        hip_tlv_len_t contents_size)
{
    hip_calc_generic_param_len(tlv_common,
                               sizeof(struct hip_tlv_common),
                               contents_size);
}

/**
 * Return a sting for a given parameter type number for diagnostics.
 * The returned string should be just the same as its type constant name.
 *
 * @note If you added a HIP_MSG_NEWMODE in lib/core/icomm.h, you also need to
 *       add a case block for your HIP_MSG_NEWMODE constant in the
 *       switch(msg_type) block in this function.
 * @param msg_type message type number
 * @return the name of the message type
 */
const char *hip_message_type_name(const uint8_t msg_type)
{
    switch (msg_type) {
    case HIP_I1:            return "HIP_I1";
    case HIP_R1:            return "HIP_R1";
    case HIP_I2:            return "HIP_I2";
    case HIP_R2:            return "HIP_R2";
    case HIP_UPDATE:        return "HIP_UPDATE";
    case HIP_NOTIFY:        return "HIP_NOTIFY";
    case HIP_CLOSE:         return "HIP_CLOSE";
    case HIP_CLOSE_ACK:     return "HIP_CLOSE_ACK";
    case HIP_CER:           return "HIP_CER";
    case HIP_PAYLOAD:       return "HIP_PAYLOAD";
    case HIP_PSIG:          return "HIP_PSIG";
    case HIP_TRIG:          return "HIP_TRIG";
    case HIP_MSG_ADD_LOCAL_HI:       return "HIP_MSG_ADD_LOCAL_HI";
    case HIP_MSG_DEL_LOCAL_HI:       return "HIP_MSG_DEL_LOCAL_HI";
    case HIP_MSG_RUN_UNIT_TEST:      return "HIP_MSG_RUN_UNIT_TEST";
    case HIP_MSG_RST:                return "HIP_MSG_RST";
    case HIP_MSG_UNIT_TEST:          return "HIP_MSG_UNIT_TEST";
    case HIP_MSG_NETLINK_DUMMY:      return "HIP_MSG_NETLINK_DUMMY";
    case HIP_MSG_CONF_PUZZLE_NEW:    return "HIP_MSG_CONF_PUZZLE_NEW";
    case HIP_MSG_CONF_PUZZLE_GET:    return "HIP_MSG_CONF_PUZZLE_GET";
    case HIP_MSG_CONF_PUZZLE_SET:    return "HIP_MSG_CONF_PUZZLE_SET";
    case HIP_MSG_CONF_PUZZLE_INC:    return "HIP_MSG_CONF_PUZZLE_INC";
    case HIP_MSG_CONF_PUZZLE_DEC:    return "HIP_MSG_CONF_PUZZLE_DEC";
    case HIP_MSG_SET_OPPORTUNISTIC_MODE: return "HIP_MSG_SET_OPPORTUNISTIC_MODE";
    case HIP_MSG_SET_DEBUG_ALL:      return "HIP_MSG_SET_DEBUG_ALL";
    case HIP_MSG_SET_DEBUG_MEDIUM:   return "HIP_MSG_SET_DEBUG_MEDIUM";
    case HIP_MSG_SET_DEBUG_NONE:     return "HIP_MSG_SET_DEBUG_NONE";
    case HIP_MSG_MHADDR_ACTIVE:      return "HIP_MSG_MHADDR_ACTIVE";
    case HIP_MSG_MHADDR_LAZY:        return "HIP_MSG_MHADDR_LAZY";
    case HIP_MSG_RESTART:            return "HIP_MSG_RESTART";
    case HIP_MSG_SET_LOCATOR_ON:     return "HIP_MSG_SET_LOCATOR_ON";
    case HIP_MSG_SET_LOCATOR_OFF:    return "HIP_MSG_SET_LOCATOR_OFF";
    case HIP_MSG_HIT_TO_IP_ON:       return "HIP_MSG_HIT_TO_IP_ON";
    case HIP_MSG_HIT_TO_IP_OFF:      return "HIP_MSG_HIT_TO_IP_OFF";
    case HIP_MSG_HIT_TO_IP_SET:      return "HIP_MSG_HIT_TO_IP_SET";
    case HIP_MSG_SET_OPPTCP_ON:      return "HIP_MSG_SET_OPPTCP_ON";
    case HIP_MSG_SET_OPPTCP_OFF:     return "HIP_MSG_SET_OPPTCP_OFF";
    case HIP_MSG_OPPTCP_SEND_TCP_PACKET: return "HIP_MSG_OPPTCP_SEND_TCP_PACKET";
    case HIP_MSG_TRANSFORM_ORDER:    return "HIP_MSG_TRANSFORM_ORDER";
    case HIP_MSG_OFFER_RVS:          return "HIP_MSG_OFFER_RVS";
    case HIP_MSG_CANCEL_RVS:         return "HIP_MSG_CANCEL_RVS";
    case HIP_MSG_REINIT_RVS:         return "HIP_MSG_REINIT_RVS";
    case HIP_MSG_ADD_DEL_SERVER:     return "HIP_MSG_ADD_DEL_SERVER";
    case HIP_MSG_OFFER_HIPRELAY:     return "HIP_MSG_OFFER_HIPRELAY";
    case HIP_MSG_CANCEL_HIPRELAY:    return "HIP_MSG_CANCEL_HIPRELAY";
    case HIP_MSG_REINIT_RELAY:       return "HIP_MSG_REINIT_RELAY";
    case HIP_MSG_ADD_DB_HI:          return "HIP_MSG_ADD_DB_HI";
    case HIP_MSG_FIREWALL_PING:      return "HIP_MSG_FIREWALL_PING";
    case HIP_MSG_FIREWALL_PING_REPLY: return "HIP_MSG_FIREWALL_PING_REPLY";
    case HIP_MSG_FIREWALL_QUIT:      return "HIP_MSG_FIREWALL_QUIT";
    case HIP_MSG_DAEMON_QUIT:        return "HIP_MSG_DAEMON_QUIT";
    case HIP_MSG_I1_REJECT:          return "HIP_MSG_I1_REJECT";
    case HIP_MSG_SET_NAT_PLAIN_UDP:  return "HIP_MSG_SET_NAT_PLAIN_UDP";
    case HIP_MSG_SET_NAT_NONE:       return "HIP_MSG_SET_NAT_NONE";
    case HIP_MSG_FW_BEX_DONE:        return "HIP_MSG_FW_BEX_DONE";
    case HIP_MSG_IPSEC_ADD_SA:       return "HIP_MSG_IPSEC_ADD_SA";
    case HIP_MSG_USERSPACE_IPSEC:    return "HIP_MSG_USERSPACE_IPSEC";
    case HIP_MSG_ESP_PROT_TFM:       return "HIP_MSG_ESP_PROT_TFM";
    case HIP_MSG_BEX_STORE_UPDATE:   return "HIP_MSG_BEX_STORE_UPDATE";
    case HIP_MSG_TRIGGER_UPDATE:     return "HIP_MSG_TRIGGER_UPDATE";
    case HIP_MSG_ANCHOR_CHANGE:      return "HIP_MSG_ANCHOR_CHANGE";
    case HIP_MSG_TRIGGER_BEX:        return "HIP_MSG_TRIGGER_BEX";
    case HIP_MSG_GET_PEER_HIT:       return "HIP_MSG_GET_PEER_HIT";
    case HIP_MSG_NSUPDATE_ON:        return "HIP_MSG_NSUPDATE_ON";
    case HIP_MSG_NSUPDATE_OFF:       return "HIP_MSG_NSUPDATE_OFF";
    case HIP_MSG_HEARTBEAT:          return "HIP_MSG_HEARTBEAT";
    case HIP_MSG_SET_NAT_PORT:       return "HIP_MSG_SET_NAT_PORT";
    case HIP_MSG_SIGN_BUDDY_X509V3:  return "HIP_MSG_SIGN_BUDDY_X509V3";
    case HIP_MSG_SIGN_BUDDY_SPKI:    return "HIP_MSG_SIGN_BUDDY_SPKI";
    case HIP_MSG_VERIFY_BUDDY_X509V3: return "HIP_MSG_VERIFY_BUDDY_X509V3";
    case HIP_MSG_VERIFY_BUDDY_SPKI:  return "HIP_MSG_VERIFY_BUDDY_SPKI";
    case HIP_MSG_MAP_ID_TO_ADDR:     return "HIP_MSG_MAP_ID_TO_ADDR";
    case HIP_MSG_OFFER_FULLRELAY:    return "HIP_MSG_OFFER_FULLRELAY";
    case HIP_MSG_CANCEL_FULLRELAY:   return "HIP_MSG_CANCEL_FULLRELAY";
    case HIP_MSG_REINIT_FULLRELAY:   return "HIP_MSG_REINIT_FULLRELAY";
    case HIP_MSG_FIREWALL_START:     return "HIP_MSG_FIREWALL_START";
    case HIP_MSG_MANUAL_UPDATE_PACKET: return "HIP_MSG_MANUAL_UPDATE_PACKET";
    default:
        return "UNDEFINED";
    }
}

#ifdef CONFIG_HIP_DEBUG
/**
 * Return a string for a given parameter type number for diagnostics.
 *
 * @param param_type parameter type number
 * @return      name of the message type
 */
static const char *hip_param_type_name(const hip_tlv_type_t param_type)
{
    switch (param_type) {
    case HIP_PARAM_ACK:             return "HIP_PARAM_ACK";
    case HIP_PARAM_CERT:            return "HIP_PARAM_CERT";
    case HIP_PARAM_DH_SHARED_KEY:   return "HIP_PARAM_DH_SHARED_KEY";
    case HIP_PARAM_DIFFIE_HELLMAN:  return "HIP_PARAM_DIFFIE_HELLMAN";
    case HIP_PARAM_DSA_SIGN_DATA:   return "HIP_PARAM_DSA_SIGN_DATA";
    case HIP_PARAM_DST_ADDR:        return "HIP_PARAM_DST_ADDR";
    case HIP_PARAM_ECHO_REQUEST:    return "HIP_PARAM_ECHO_REQUEST";
    case HIP_PARAM_ECHO_REQUEST_SIGN: return "HIP_PARAM_ECHO_REQUEST_SIGN";
    case HIP_PARAM_ECHO_REQUEST_M:  return "HIP_PARAM_ECHO_REQUEST_M";
    case HIP_PARAM_ECHO_RESPONSE:   return "HIP_PARAM_ECHO_RESPONSE";
    case HIP_PARAM_ECHO_RESPONSE_SIGN: return "HIP_PARAM_ECHO_RESPONSE_SIGN";
    case HIP_PARAM_ECHO_RESPONSE_M: return "HIP_PARAM_ECHO_RESPONSE_M";
    case HIP_PARAM_EID_ADDR:        return "HIP_PARAM_EID_ADDR";
    case HIP_PARAM_EID_ENDPOINT:    return "HIP_PARAM_EID_ENDPOINT";
    case HIP_PARAM_EID_IFACE:       return "HIP_PARAM_EID_IFACE";
    case HIP_PARAM_EID_SOCKADDR:    return "HIP_PARAM_EID_SOCKADDR";
    case HIP_PARAM_ENCAPS_MSG:      return "HIP_PARAM_ENCAPS_MSG";
    case HIP_PARAM_ENCRYPTED:       return "HIP_PARAM_ENCRYPTED";
    case HIP_PARAM_ESP_INFO:        return "HIP_PARAM_ESP_INFO";
    case HIP_PARAM_ESP_TRANSFORM:   return "HIP_PARAM_ESP_TRANSFORM";
    case HIP_PARAM_FROM_PEER:       return "HIP_PARAM_FROM_PEER";
    case HIP_PARAM_FROM:            return "HIP_PARAM_FROM";
    case HIP_PARAM_HA_INFO:         return "HIP_PARAM_HA_INFO";
    case HIP_PARAM_HASH_CHAIN_ANCHORS: return "HIP_PARAM_HASH_CHAIN_ANCHORS";
    case HIP_PARAM_HASH_CHAIN_PSIG: return "HIP_PARAM_HASH_CHAIN_PSIG";
    case HIP_PARAM_HASH_CHAIN_VALUE: return "HIP_PARAM_HASH_CHAIN_VALUE";
    case HIP_PARAM_HIP_SIGNATURE2:  return "HIP_PARAM_HIP_SIGNATURE2";
    case HIP_PARAM_HIP_SIGNATURE:   return "HIP_PARAM_HIP_SIGNATURE";
    case HIP_PARAM_HIP_TRANSFORM:   return "HIP_PARAM_HIP_TRANSFORM";
    case HIP_PARAM_HI:              return "HIP_PARAM_HI";
    case HIP_PARAM_HIT:             return "HIP_PARAM_HIT";
    case HIP_PARAM_HIT_LOCAL:       return "HIP_PARAM_HIT_LOCAL";
    case HIP_PARAM_HIT_PEER:        return "HIP_PARAM_HIT_PEER";
    case HIP_PARAM_HMAC2:           return "HIP_PARAM_HMAC2";
    case HIP_PARAM_HMAC:            return "HIP_PARAM_HMAC";
    case HIP_PARAM_HOST_ID:         return "HIP_PARAM_HOST_ID";
    case HIP_PARAM_INT:             return "HIP_PARAM_INT";
    case HIP_PARAM_IPV6_ADDR:       return "HIP_PARAM_IPV6_ADDR";
    case HIP_PARAM_IPV6_ADDR_LOCAL: return "HIP_PARAM_IPV6_ADDR_LOCAL";
    case HIP_PARAM_IPV6_ADDR_PEER:  return "HIP_PARAM_IPV6_ADDR_PEER";
    case HIP_PARAM_KEYS:            return "HIP_PARAM_KEYS";
    case HIP_PARAM_LOCATOR:         return "HIP_PARAM_LOCATOR";
    case HIP_PARAM_NOTIFICATION:    return "HIP_PARAM_NOTIFICATION";
    case HIP_PARAM_PORTPAIR:        return "HIP_PARAM_PORTPAIR";
    case HIP_PARAM_PUZZLE:          return "HIP_PARAM_PUZZLE";
    case HIP_PARAM_CHALLENGE_REQUEST:       return "HIP_PARAM_CHALLENGE_REQUEST";
    case HIP_PARAM_R1_COUNTER:      return "HIP_PARAM_R1_COUNTER";
    case HIP_PARAM_REG_FAILED:      return "HIP_PARAM_REG_FAILED";
    case HIP_PARAM_REG_FROM:        return "HIP_PARAM_REG_FROM";
    case HIP_PARAM_REG_INFO:        return "HIP_PARAM_REG_INFO";
    case HIP_PARAM_REG_REQUEST:     return "HIP_PARAM_REG_REQUEST";
    case HIP_PARAM_REG_RESPONSE:    return "HIP_PARAM_REG_RESPONSE";
    case HIP_PARAM_RELAY_FROM:      return "HIP_PARAM_RELAY_FROM";
    case HIP_PARAM_RELAY_HMAC:      return "HIP_PARAM_RELAY_HMAC";
    case HIP_PARAM_RELAY_TO:        return "HIP_PARAM_RELAY_TO";
    case HIP_PARAM_RVS_HMAC:        return "HIP_PARAM_RVS_HMAC";
    case HIP_PARAM_SEQ:             return "HIP_PARAM_SEQ";
    case HIP_PARAM_SOLUTION:        return "HIP_PARAM_SOLUTION";
    case HIP_PARAM_CHALLENGE_RESPONSE:      return "HIP_PARAM_CHALLENGE_RESPONSE";
    case HIP_PARAM_SRC_ADDR:        return "HIP_PARAM_SRC_ADDR";
    case HIP_PARAM_TO_PEER:         return "HIP_PARAM_TO_PEER";
    case HIP_PARAM_UINT:            return "HIP_PARAM_UINT";
    case HIP_PARAM_UNIT_TEST:       return "HIP_PARAM_UNIT_TEST";
    case HIP_PARAM_VIA_RVS:         return "HIP_PARAM_VIA_RVS";
    case HIP_PARAM_PSEUDO_HIT:      return "HIP_PARAM_PSEUDO_HIT";
    case HIP_PARAM_HCHAIN_ANCHOR:   return "HIP_PARAM_HCHAIN_ANCHOR";
    case HIP_PARAM_ESP_PROT_TRANSFORMS: return "HIP_PARAM_ESP_PROT_TRANSFORMS";
    case HIP_PARAM_ESP_PROT_ANCHOR: return "HIP_PARAM_ESP_PROT_ANCHOR";
    case HIP_PARAM_ESP_PROT_BRANCH: return "HIP_PARAM_ESP_PROT_BRANCH";
    case HIP_PARAM_ESP_PROT_SECRET: return "HIP_PARAM_ESP_PROT_SECRET";
    case HIP_PARAM_ESP_PROT_ROOT: return "HIP_PARAM_ESP_PROT_ROOT";
    //add by santtu
    case HIP_PARAM_NAT_TRANSFORM:   return "HIP_PARAM_NAT_TRANSFORM";
    case HIP_PARAM_NAT_PACING:      return "HIP_PARAM_NAT_PACING";
    //end add
    case HIP_PARAM_LSI:             return "HIP_PARAM_LSI";
    case HIP_PARAM_SRC_TCP_PORT:    return "HIP_PARAM_SRC_TCP_PORT";
    case HIP_PARAM_DST_TCP_PORT:    return "HIP_PARAM_DST_TCP_PORT";
    case HIP_PARAM_STUN:            return "HIP_PARAM_STUN";
    case HIP_PARAM_HOSTNAME:        return "HIP_PARAM_HOSTNAME";
        //end add
    }
    return "UNDEFINED";
}
#endif /* CONFIG_HIP_DEBUG */

/**
 * Print the contents of a message using HIP debug interface for diagnostics
 *
 * @param msg a pointer to the message to be printed.
 * @note      Do not call this function directly, use the HIP_DUMP_MSG() macro
 *            instead.
 */
void hip_dump_msg(const struct hip_common *msg)
{
    const struct hip_tlv_common *current_param = NULL;
    const uint8_t *contents                    = NULL;
    /* The value of the "Length"-field in current parameter. */
    hip_tlv_len_t len                    = 0;
    /* Total length of the parameter (type+length+value+padding), and the
     * length of padding. */
    size_t total_len                     = 0, pad_len = 0;
    HIP_DEBUG("--------------- MSG START ------------------\n");

    HIP_DEBUG("Msg type :      %s (%d)\n",
              hip_message_type_name(hip_get_msg_type(msg)),
              hip_get_msg_type(msg));
    HIP_DEBUG("Msg length:     %d\n", hip_get_msg_total_len(msg));
    HIP_DEBUG("Msg err:        %d\n", hip_get_msg_err(msg));
    HIP_DEBUG("Msg controls:   0x%04x\n", msg->control);

    while ((current_param = hip_get_next_param(msg, current_param))) {
        len       = hip_get_param_contents_len(current_param);
        /* Formula from base draft section 5.2.1. */
        total_len = 11 + len - (len + 3) % 8;
        pad_len   = total_len - len - sizeof(hip_tlv_type_t)
                    - sizeof(hip_tlv_len_t);
        contents  = hip_get_param_contents_direct(current_param);
        HIP_DEBUG("Parameter type:%s (%d). Total length: %d (4 type+" \
                  "length, %d content, %d padding).\n",
                  hip_param_type_name(hip_get_param_type(current_param)),
                  hip_get_param_type(current_param),
                  total_len,
                  len,
                  pad_len);
        HIP_HEXDUMP("Contents:", contents, len);
        HIP_HEXDUMP("Padding:", contents + len, pad_len);
    }
    HIP_DEBUG("---------------- MSG END --------------------\n");
}

/**
 * check a user (interprocess) message for integrity
 *
 * @param msg the message to be verified for integrity
 * @return zero if the message was ok, or negative error value on error.
 */
int hip_check_userspace_msg(const struct hip_common *msg)
{
    const struct hip_tlv_common *current_param = NULL;
    int err                                    = 0;

    if (!hip_check_user_msg_len(msg)) {
        err = -EMSGSIZE;
        HIP_ERROR("bad msg len %d\n", hip_get_msg_total_len(msg));
        goto out;
    }

    while ((current_param = hip_get_next_param(msg, current_param))) {
        if (!hip_check_param_contents_len(msg, current_param)) {
            err = -EMSGSIZE;
            HIP_ERROR("bad param len\n");
            break;
        } else if (!hip_check_userspace_param_type(current_param)) {
            err = -EINVAL;
            HIP_ERROR("bad param type\n");
            break;
        }
    }

out:
    return err;
}

/**
 * Check the attributes of a parameter.
 * This is the function where one can test special attributes such as algo,
 * groupid, suiteid, etc of a HIP parameter. If the parameter does not require
 * other than just the validation of length and type fields, one should not
 * add any checks for that parameter here.
 *
 * @param param the parameter to checked
 * @return zero if the message was ok, or negative error value on error.
 *
 * @todo this function may be unneccessary because the input handlers
 *       already do some checking. Currently they are double checked..
 */
static int hip_check_network_param_attributes(const struct hip_tlv_common *param)
{
    hip_tlv_type_t type = hip_get_param_type(param);
    int err             = 0;

    switch (type) {
    case HIP_PARAM_HIP_TRANSFORM:
    case HIP_PARAM_ESP_TRANSFORM:
    {
        /* Search for one supported transform */
        hip_transform_suite_t suite;

        suite = hip_get_param_transform_suite_id(param);
        if (suite == 0) {
            HIP_ERROR("Could not find suitable %s transform\n",
                      type == HIP_PARAM_HIP_TRANSFORM ? "HIP" : "ESP");
            err = -EPROTONOSUPPORT;
        }
        break;
    }
    case HIP_PARAM_HOST_ID:
    {
        uint8_t algo =
            hip_get_host_id_algo((const struct hip_host_id *) param);
        if (algo != HIP_HI_DSA && algo != HIP_HI_RSA) {
            err = -EPROTONOSUPPORT;
            HIP_ERROR("Host id algo %d not supported\n", algo);
        }
        break;
    }
    }
    return err;
}

/**
 * check a network (on-the-wire) message for integrity
 *
 * @param msg the message to be verified for integrity
 * @return zero if the message was ok, or negative error value on error.
 */
int hip_check_network_msg(const struct hip_common *msg)
{
    const struct hip_tlv_common *current_param = NULL;
    hip_tlv_type_t current_param_type          = 0, prev_param_type = 0;
    int err                                    = 0;

    /* Checksum of the message header is verified in input.c */

    if (!hip_check_network_msg_type(msg)) {
        err = -EINVAL;
        HIP_ERROR("bad msg type (%d)\n", hip_get_msg_type(msg));
        goto out;
    }

    /* check msg length */
    if (!hip_check_network_msg_len(msg)) {
        err = -EMSGSIZE;
        HIP_ERROR("bad msg len %d\n", hip_get_msg_total_len(msg));
        goto out;
    }

    /* Checking of param types, lengths and ordering. */
    while ((current_param = hip_get_next_param(msg, current_param))) {
        current_param_type = hip_get_param_type(current_param);
        if (!hip_check_param_contents_len(msg, current_param)) {
            err = -EMSGSIZE;
            HIP_ERROR("bad param len\n");
            break;
        } else if (!hip_check_network_param_type(current_param)) {
            err = -EINVAL;
            HIP_ERROR("bad param type, current param=%u\n",
                      hip_get_param_type(current_param));
            break;
        } else if (current_param_type < prev_param_type &&
                   ((current_param_type < HIP_LOWER_TRANSFORM_TYPE ||
                     current_param_type > HIP_UPPER_TRANSFORM_TYPE) &&
                    (prev_param_type < HIP_LOWER_TRANSFORM_TYPE ||
                             prev_param_type > HIP_UPPER_TRANSFORM_TYPE))) {
            /* According to draft-ietf-hip-base-03 parameter type order
             * strictly enforced, except for
             * HIP_LOWER_TRANSFORM_TYPE - HIP_UPPER_TRANSFORM_TYPE
             */
            err = -ENOMSG;
            HIP_ERROR("Wrong order of parameters (%d, %d)\n",
                      prev_param_type, current_param_type);
            break;
        } else if (hip_check_network_param_attributes(current_param)) {
            HIP_ERROR("bad param attributes\n");
            err = -EINVAL;
            break;
        }
        prev_param_type = current_param_type;
    }

out:
    return err;
}

/**
 * Build and insert a parameter provided in multiple pieces into a message.
 *
 * This is the root function of all parameter building functions.
 * hip_build_param() and hip_build_param_contents() both  use this function to
 * append the parameter into the HIP message. This function updates the message
 * header length to keep the next free parameter slot quickly accessible for
 * faster writing of the parameters. This function also automagically adds zero
 * filled padding to the parameter, to keep its total length in multiple of 8
 * bytes. Parameter contents are copied from the function parameter @c contents,
 * thus the contents can and should be allocated from the stack instead of the
 * heap (i.e. allocated with malloc()).
 *
 * @param msg            the message where the parameter is to be appended
 * @param parameter_hdr  pointer to the header of the parameter
 * @param param_hdr_size size of parameter_hdr structure (in host byte order)
 * @param contents       the contents of the parameter; the data to be inserted
 *                       after the parameter_hdr (in host byte order)
 * @return               zero on success, or negative on error
 * @see                  hip_build_param().
 * @see                  hip_build_param_contents().
 */
static int hip_build_generic_param(struct hip_common *msg,
                                   const void *parameter_hdr,
                                   hip_tlv_len_t param_hdr_size,
                                   const void *contents)
{
    const struct hip_tlv_common *param = parameter_hdr;
    const void *src                    = NULL;
    uint8_t *dst                       = NULL;
    int err                            = 0, size = 0;
    uint8_t *max_dst                   = ((uint8_t *) msg) + HIP_MAX_PACKET;

    if (msg == NULL) {
        HIP_ERROR("Message is NULL.\n");
        err = -EFAULT;
        goto out;
    }

    if (contents == NULL) {
        HIP_ERROR("Parameter contents to build is NULL.\n");
        err = -EFAULT;
        goto out;
    }

    if (param_hdr_size < sizeof(struct hip_tlv_common)) {
        HIP_ERROR("Size of the parameter build is too small.\n");
        err = -EMSGSIZE;
        goto out;
    }

    dst = hip_find_free_param(msg);
    if (dst == NULL) {
        err = -EMSGSIZE;
        HIP_ERROR("The message has no room for new parameters.\n");
        goto out;
    }

    if (dst + hip_get_param_total_len(param) > max_dst) {
        err = -EMSGSIZE;
        HIP_ERROR("The parameter to build does not fit in the message " \
                  "because if the parameter would be appended to " \
                  "the message, maximum HIP packet length would be " \
                  "exceeded." \
                  "len: %d\n",
                  hip_get_param_contents_len(param));
        goto out;
    }

    /* copy header */
    src  = param;
    size = param_hdr_size;
    memcpy(dst, src, size);

    /* copy contents  */
    dst += param_hdr_size;
    src  = contents;
    /* Copy the right amount of contents, see jokela draft for TLV
     * format. For example, this skips the algo in struct hip_sig2
     * (which is included in the length), see the
     * build_param_signature2_contents() function below. */
    size = hip_get_param_contents_len(param) -
           (param_hdr_size - sizeof(struct hip_tlv_common));
    memcpy(dst, src, size);

    /* we have to update header length or otherwise hip_find_free_param
     * will fail when it checks the header length */
    hip_calc_hdr_len(msg);
    if (hip_get_msg_total_len(msg) == 0) {
        HIP_ERROR("Could not calculate temporary header length.\n");
        err = -EFAULT;
    }

out:

    return err;
}

/**
 * Build and append parameter contents (i.e. the part after the type
 * and length fields) into a message.
 *
 * This function differs from hip_build_generic_param only because it
 * assumes that the parameter header is just sizeof(struct hip_tlv_common).
 * This function updates the message header length to keep the next free
 * parameter slot quickly accessible for faster writing of the parameters.
 * This function automagically adds zero filled paddign to the parameter,
 * to keep its total length in multiple of 8 bytes.
 *
 * @param msg           the message where the parameter will be appended.
 * @param contents      the data after the type and length fields.
 * @param param_type    the type of the parameter (in host byte order).
 * @param contents_size the size of contents (in host byte order).
 * @return              zero on success, or negative on error.
 * @see                 hip_build_generic_param().
 * @see                 hip_build_param().
 */
int hip_build_param_contents(struct hip_common *msg,
                             const void *contents,
                             hip_tlv_type_t param_type,
                             hip_tlv_len_t contents_size)
{
    struct hip_tlv_common param;
    hip_set_param_type(&param, param_type);
    hip_set_param_contents_len((struct hip_tlv_common *) &param, contents_size);
    return hip_build_generic_param(msg,
                                   &param,
                                   sizeof(struct hip_tlv_common),
                                   contents);
}

/**
 * Append a prebuilt parameter into a HIP message.
 *
 * Appends a complete network byte ordered parameter @c tlv_common into a HIP
 * message @c msg. This function differs from hip_build_param_contents() and
 * hip_build_generic_param() because it takes a complete network byte ordered
 * parameter as its input. It means that this function can be used for e.g.
 * copying a parameter from a message to another.
 *
 * This function updates the message header length to keep the next free
 * parameter slot quickly accessible for faster writing of the parameters. This
 * function automagically adds zero filled paddign to the parameter, to keep its
 * total length in multiple of 8 bytes.
 *
 * @param msg        a pointer to a message where the parameter will be
 *                   appended.
 * @param tlv_common a pointer to the network byte ordered parameter that will
 *                   be appended into the message.
 * @return           zero on success, or negative error value on error.
 * @see              hip_build_generic_param().
 * @see              hip_build_param_contents().
 */
int hip_build_param(struct hip_common *msg, const void *tlv_common)
{
    int err        = 0;
    const uint8_t *contents = ((const uint8_t *) tlv_common) + sizeof(struct hip_tlv_common);

    if (tlv_common == NULL) {
        err = -EFAULT;
        HIP_ERROR("param null\n");
        goto out;
    }

    err = hip_build_param_contents(msg, contents,
                                   hip_get_param_type(tlv_common),
                                   hip_get_param_contents_len(tlv_common));
    if (err) {
        HIP_ERROR("could not build contents (%d)\n", err);
    }

out:
    return err;
}

/**
 * set whether to request for a response from hipd or not
 *
 * @param msg user message
 * @param on 1 if requesting for a response, otherwise 0
 */
void hip_set_msg_response(struct hip_common *msg, uint8_t on)
{
    if (msg->ver_res == HIP_USER_VER_RES) {
        msg->control = on;
    } else {
        msg->payload_proto = on;
    }
}

/**
 * check if the user message requires response from hipd
 *
 * @param msg user message
 * @return 1 if message requires response, other 0
 */
uint8_t hip_get_msg_response(struct hip_common *msg)
{
    return msg->ver_res == HIP_USER_VER_RES ? msg->control : msg->payload_proto;
}

/**
 * builds a header for interprocess communication.
 *
 * This function builds the header that can be used for HIP kernel-userspace
 * communication. It is commonly used by the daemon, hipconf, resolver or
 * the kernel module itself. This function should be called before
 * building the parameters for the message.
 *
 * This function does not write the header length into the message. It should
 * be written by the build_param_functions.
 *
 * @param msg       the message where the userspace header is to be written.
 * @param base_type the type of the message.
 * @param err_val   a positive error value to be communicated for the receiver
 *                  (usually just zero for no errors).
 * @return          zero on success, or negative on error.
 * @note This function overloads the HIP header for interprocess communications
 *       between hipd, hipfw and hipconf. See the internals of this function
 *       how the fields in the header are overloaded. This kind of messages
 *       should never be sent on wire and should not be confused with message
 *       arriving from the network.
 */
int hip_build_user_hdr(struct hip_common *msg, hip_hdr_type_t base_type,
                       hip_hdr_err_t err_val)
{
    int err = 0;

    HIP_IFEL(!msg, -EINVAL, "null msg\n");

    /* build header first and then parameters */
    HIP_ASSERT(hip_get_msg_total_len(msg) == 0);

    /* Use internal message version of header.
     * This allows for messages longer than HIP_MAX_NETWORK_PACKET. */
    msg->ver_res = HIP_USER_VER_RES;

    hip_set_msg_type(msg, base_type);
    hip_set_msg_err(msg, err_val);
    /* Note: final header length is usually calculated by the
     * last call to build_param() but it is possible to build a
     * msg with just the header, so we have to calculate the
     * header length anyway. */
    hip_calc_hdr_len(msg);

    HIP_IFE(hip_get_msg_total_len(msg) == 0, -EMSGSIZE);
    HIP_IFEL(!hip_check_user_msg_len(msg),
             -EMSGSIZE,
             "hipd build hdr: msg len (%d) invalid\n",
             hip_get_msg_total_len(msg));

out_err:
    return err;
}

/**
 * Write a network header into a HIP control message.
 *
 * This function does not write the header length into the message. It should
 * be written by the build_param_functions. The checksum field is not written
 * either because it is done in hip_send_pkt().
 *
 * @param msg          the message where the HIP network should be written
 * @param type_hdr     the type of the HIP header as specified in the drafts
 * @param control      HIP control bits in host byte order
 * @param hit_sender   source HIT in network byte order
 * @param hit_receiver destination HIT in network byte order
 * @todo build HIP network header in the same fashion as in build_daemon_hdr().
 * <ul>
 * <li>Write missing headers in the header using accessor functions
 * (see hip_get/set_XXX() functions in the beginning of this file). You have to
 * create couple of new ones, but daemon and network messages use the same
 * locations for storing len and type (hip_common->err is stored in the
 * hip_common->checksum) and they can be used as they are.</li>
 * <li>payload_proto.</li>
 * <li>payload_len: see how build_daemon_hdr() works.</li>
 * <li>ver_res.</li>
 * <li>write the parameters of this function into the message.</li>
 * </ul>
 * @note Use @b only accessors to hide byte order and size conversion issues!
 */
void hip_build_network_hdr(struct hip_common *msg, uint8_t type_hdr,
                           uint16_t control, const struct in6_addr *hit_sender,
                           const struct in6_addr *hit_receiver)
{
    /* build header first and then parameters */
    HIP_ASSERT(hip_get_msg_total_len(msg) == 0);

    msg->payload_proto = IPPROTO_NONE;     /* 1 byte, no htons()    */
    /* Do not touch the length; it is written by param builders */
    msg->type_hdr      = type_hdr;             /* 1 byte, no htons()    */
    /* version includes the SHIM6 bit */
    msg->ver_res       = (HIP_VER_RES << 4) | 1; /* 1 byte, no htons() */

    msg->control       = htons(control);
    msg->checksum      = htons(0); /* this will be written by xmit */

    ipv6_addr_copy(&msg->hits, hit_sender ? hit_sender : &in6addr_any);
    ipv6_addr_copy(&msg->hitr, hit_receiver ? hit_receiver : &in6addr_any);
}

/**
 * Builds a @c HMAC parameter to the HIP packet @c msg. This function calculates
 * also the hmac value from the whole message as specified in the drafts.
 *
 * @param msg a pointer to the message where the @c HMAC parameter will be
 *            appended.
 * @param key a pointer to a key used for hmac.
 * @param param_type HIP_PARAM_HMAC, HIP_PARAM_RELAY_HMAC or HIP_PARAM_RVS_HMAC accordingly
 * @return    zero on success, or negative error value on error.
 * @see       hip_build_param_hmac2_contents()
 * @see       hip_write_hmac().
 */
int hip_build_param_hmac(struct hip_common *msg,
                         const struct hip_crypto_key *key,
                         hip_tlv_type_t param_type)
{
    int err = 0;
    struct hip_hmac hmac;

    hip_set_param_type((struct hip_tlv_common *)  &hmac, param_type);
    hip_calc_generic_param_len((struct hip_tlv_common *) &hmac,
                               sizeof(struct hip_hmac),
                               0);

    HIP_IFEL(hip_write_hmac(HIP_DIGEST_SHA1_HMAC, key->key, msg,
                            hip_get_msg_total_len(msg),
                            hmac.hmac_data), -EFAULT,
             "Error while building HMAC\n");

    err = hip_build_param(msg, &hmac);
out_err:
    return err;
}

/**
 * Builds a @c HIP_PARAM_HMAC parameter to the HIP packet @c msg. This function calculates
 * also the hmac value from the whole message as specified in the drafts.
 *
 * @param msg a pointer to the message where the @c HMAC parameter will be
 *            appended.
 * @param key a pointer to a key used for hmac.
 * @return    zero on success, or negative error value on error.
 * @see       hip_build_param_hmac_contents()
 */
int hip_build_param_hmac_contents(struct hip_common *msg,
                                  const struct hip_crypto_key *key)
{
    return hip_build_param_hmac(msg, key, HIP_PARAM_HMAC);
};

/**
 * calculate and create a HMAC2 parameter that includes also a host id
 * which is not included in the message
 *
 * @param msg a HIP control message from the HMAC should be calculated from
 * @param msg_copy an extra, temporary buffer allocated by the caller
 * @param host_id the host id parameter that should be included in the calculated
 *                HMAC value
 * @return zero for success and negative on failure
 */
int hip_create_msg_pseudo_hmac2(const struct hip_common *msg,
                                struct hip_common *msg_copy,
                                struct hip_host_id *host_id)
{
    const struct hip_tlv_common *param = NULL;
    int err                            = 0;

    HIP_HEXDUMP("host id", host_id,
                hip_get_param_total_len(host_id));

    memcpy(msg_copy, msg, sizeof(struct hip_common));
    hip_set_msg_total_len(msg_copy, 0);
    hip_zero_msg_checksum(msg_copy);

    /* copy parameters to a temporary buffer to calculate
     * pseudo-hmac (includes the host id) */
    while ((param = hip_get_next_param(msg, param)) &&
           hip_get_param_type(param) < HIP_PARAM_HMAC2)
    {
        HIP_IFEL(hip_build_param(msg_copy, param),
                 -1,
                 "Failed to build param\n");
    }

    // we need to rebuild the compressed parameter format for host ids
    HIP_IFEL(hip_build_param_host_id(msg_copy, host_id), -1,
             "Failed to append pseudo host id to R2\n");

out_err:
    return err;
}

/**
 * Builds a @c HMAC2 parameter.
 *
 * Builds a @c HMAC2 parameter to the HIP packet @c msg. This function
 * calculates also the hmac value from the whole message as specified in the
 * drafts. Assumes that the hmac includes only the header and host id.
 *
 * @param msg      a pointer to the message where the @c HMAC2 parameter will be
 *                 appended.
 * @param key      a pointer to a key used for hmac.
 * @param host_id  a pointer to a host id.
 * @return         zero on success, or negative error value on error.
 * @see            hip_build_param_hmac_contents().
 * @see            hip_write_hmac().
 */
int hip_build_param_hmac2_contents(struct hip_common *msg,
                                   struct hip_crypto_key *key,
                                   struct hip_host_id *host_id)
{
    struct hip_hmac hmac2;
    struct hip_common *msg_copy = NULL;
    int err                     = 0;

    HIP_IFEL(!(msg_copy = hip_msg_alloc()), -ENOMEM, "Message alloc\n");

    HIP_IFEL(hip_create_msg_pseudo_hmac2(msg, msg_copy, host_id), -1,
             "pseudo hmac pkt failed\n");

    hip_set_param_type((struct hip_tlv_common *)  &hmac2, HIP_PARAM_HMAC2);
    hip_calc_generic_param_len((struct hip_tlv_common *) &hmac2,
                               sizeof(struct hip_hmac),
                               0);

    HIP_IFEL(hip_write_hmac(HIP_DIGEST_SHA1_HMAC, key->key, msg_copy,
                            hip_get_msg_total_len(msg_copy),
                            hmac2.hmac_data),
                            -EFAULT,
             "Error while building HMAC\n");

    err = hip_build_param(msg, &hmac2);
out_err:
    free(msg_copy);
    return err;
}

/**
 * sanity checking for a HIP control packet originating from the network
 *
 * @param hip_common
 * @param src  The source address of the packet as a sockaddr_in or sockaddr_in6
 *             structure in network byte order. IPv6 mapped addresses are not supported.
 * @param dst  The destination address of the packet as a sockaddr_in or sockaddr_in6
 *             structure in network byte order. IPv6 mapped addresses are not supported.
 * @param len  the length of the control packet in bytes (including padding)
 * @return zero if the packet seems sane or negative otherwise
 */
int hip_verify_network_header(struct hip_common *hip_common,
                              struct sockaddr *src, struct sockaddr *dst,
                              int len)
{
    int err = 0, plen, checksum;

    plen = hip_get_msg_total_len(hip_common);

    /* Currently no support for piggybacking */
    HIP_IFEL(len != hip_get_msg_total_len(hip_common), -EINVAL,
             "Invalid HIP packet length (%d,%d). Dropping\n",
             len, plen);
    HIP_IFEL(hip_common->payload_proto != IPPROTO_NONE, -EOPNOTSUPP,
             "Protocol in packet (%u) was not IPPROTO_NONE. Dropping\n",
             hip_common->payload_proto);
    HIP_IFEL(hip_common->ver_res != ((HIP_VER_RES << 4) | 1), -EPROTOTYPE,
             "Invalid version in received packet. Dropping\n");

    HIP_IFEL(!ipv6_addr_is_hit(&hip_common->hits), -EAFNOSUPPORT,
             "Received a non-HIT in HIT-source. Dropping\n");
    HIP_IFEL(!ipv6_addr_is_hit(&hip_common->hitr) &&
             !ipv6_addr_any(&hip_common->hitr),
             -EAFNOSUPPORT,
             "Received a non-HIT or non NULL in HIT-receiver. Dropping\n");

    HIP_IFEL(ipv6_addr_any(&hip_common->hits), -EAFNOSUPPORT,
             "Received a NULL in HIT-sender. Dropping\n");

    /** @todo handle the RVS case better. */
    if (ipv6_addr_any(&hip_common->hitr)) {
        HIP_DEBUG("Received a connection to opportunistic HIT\n");
    } else {
        HIP_DEBUG_HIT("Received a connection to HIT", &hip_common->hitr);
    }

    /* Check checksum. */
    HIP_DEBUG("dst port is %d  \n", ((struct sockaddr_in *) dst)->sin_port);
    if (dst->sa_family == AF_INET && ((struct sockaddr_in *) dst)->sin_port) {
        HIP_DEBUG("HIP IPv4 UDP packet: ignoring HIP checksum\n");
    } else {
        checksum             = hip_common->checksum;
        hip_common->checksum = 0;

        HIP_IFEL(hip_checksum_packet((char *) hip_common, src, dst)
                 != checksum,
                 -EBADMSG, "HIP checksum failed.\n");

        hip_common->checksum = checksum;
    }

out_err:
    return err;
}

/**
 * build a hip_encrypted parameter
 *
 * @param msg the message where the parameter will be appended
 * @param param the parameter that will contained in the hip_encrypted
 *           parameter
 * @returns zero on success, or negative on failure
 *
 * @note This function does not actually encrypt anything, it just builds
 * the parameter. The parameter that will be encapsulated in the hip_encrypted
 * parameter has to be encrypted using a different function call.
 */
int hip_build_param_encrypted_aes_sha1(struct hip_common *msg,
                                       struct hip_tlv_common *param)
{
    int rem, err = 0;
    struct hip_encrypted_aes_sha1 enc;
    int param_len                 = hip_get_param_total_len(param);
    struct hip_tlv_common *common = param;
    char *param_padded            = NULL;

    hip_set_param_type((struct hip_tlv_common *) &enc, HIP_PARAM_ENCRYPTED);
    enc.reserved = htonl(0);
    memset(&enc.iv, 0, 16);

    /* copy the IV *IF* needed, and then the encrypted data */

    /* AES block size must be multiple of 16 bytes */
    rem = param_len % 16;
    if (rem) {
        HIP_DEBUG("Adjusting param size to AES block size\n");

        param_padded = malloc(param_len + rem);
        if (!param_padded) {
            err = -ENOMEM;
            goto out_err;
        }

        /* this kind of padding works against Ericsson/OpenSSL
         * (method 4: RFC2630 method) */
        /* http://www.di-mgt.com.au/cryptopad.html#exampleaes */
        memcpy(param_padded, param, param_len);
        memset(param_padded + param_len, rem, rem);

        common     = (struct hip_tlv_common *) param_padded;
        param_len += rem;
    }

    hip_calc_param_len((struct hip_tlv_common *) &enc, sizeof(enc) -
                       sizeof(struct hip_tlv_common) +
                       param_len);

    err = hip_build_generic_param(msg, &enc, sizeof(enc), common);

out_err:
    free(param_padded);
    return err;
}

/**
 * build the contents of a HIP signature2 parameter
 * (the type and length fields for the parameter should be set separately)
 *
 * @param msg the message
 * @param contents pointer to the signature contents (the data to be written
 *                 after the signature field)
 * @param contents_size size of the contents of the signature (the data after the
 *                 algorithm field)
 * @param algorithm the algorithm as in the HIP drafts that was used for
 *                 producing the signature
 * @return zero for success, or non-zero on error
 *
 * @note build_param_contents() is not very suitable for building a hip_sig2 struct,
 * because hip_sig2 has a troublesome algorithm field which need some special
 * attention from htons(). Thereby here is a separate builder for hip_sig2 for
 * conveniency. It uses internally hip_build_generic_param() for actually
 * writing the signature parameter into the message.
 */
int hip_build_param_signature2_contents(struct hip_common *msg,
                                        const void *contents,
                                        hip_tlv_len_t contents_size,
                                        uint8_t algorithm)
{
    /* note: if you make changes in this function, make them also in
     * build_param_signature_contents(), because it is almost the same */

    int err = 0;
    struct hip_sig2 sig2;

    HIP_ASSERT(sizeof(struct hip_sig2) >= sizeof(struct hip_tlv_common));

    hip_set_param_type((struct hip_tlv_common *) &sig2, HIP_PARAM_HIP_SIGNATURE2);
    hip_calc_generic_param_len((struct hip_tlv_common *) &sig2, sizeof(struct hip_sig2),
                               contents_size);
    sig2.algorithm = algorithm;     /* algo is 8 bits, no htons */

    err            = hip_build_generic_param(msg, &sig2,
                                             sizeof(struct hip_sig2), contents);

    return err;
}

/**
 * build the contents of a HIP signature1 parameter
 * (the type and length fields for the parameter should be set separately)
 *
 * @param msg the message
 * @param contents pointer to the signature contents (the data to be written
 *                 after the signature field)
 * @param contents_size size of the contents of the signature (the data after the
 *                 algorithm field)
 * @param algorithm the algorithm as in the HIP drafts that was used for
 *                 producing the signature
 * @return zero for success, or non-zero on error
 */
int hip_build_param_signature_contents(struct hip_common *msg,
                                       const void *contents,
                                       hip_tlv_len_t contents_size,
                                       uint8_t algorithm)
{
    /* note: if you make changes in this function, make them also in
     * build_param_signature_contents2(), because it is almost the same */

    int err = 0;
    struct hip_sig sig;

    HIP_ASSERT(sizeof(struct hip_sig) >= sizeof(struct hip_tlv_common));

    hip_set_param_type((struct hip_tlv_common *) &sig, HIP_PARAM_HIP_SIGNATURE);
    hip_calc_generic_param_len((struct hip_tlv_common *) &sig, sizeof(struct hip_sig),
                               contents_size);
    sig.algorithm = algorithm;     /* algo is 8 bits, no htons */

    err           = hip_build_generic_param(msg, &sig,
                                            sizeof(struct hip_sig), contents);

    return err;
}

/**
 * build a HIP ECHO parameter
 *
 * @param msg the message
 * @param opaque opaque data copied to the parameter
 * @param len      the length of the parameter
 * @param sign true if parameter is under signature, false otherwise
 * @param request true if parameter is ECHO_REQUEST, otherwise parameter is ECHO_RESPONSE
 * @return zero for success, or non-zero on error
 */
int hip_build_param_echo(struct hip_common *msg, const void *opaque, int len,
                         int sign, int request)
{
    struct hip_echo_request ping;
    int err;

    if (request) {
        hip_set_param_type((struct hip_tlv_common *) &ping, sign ? HIP_PARAM_ECHO_REQUEST_SIGN : HIP_PARAM_ECHO_REQUEST);
    } else {
        hip_set_param_type((struct hip_tlv_common *) &ping, sign ? HIP_PARAM_ECHO_RESPONSE_SIGN : HIP_PARAM_ECHO_RESPONSE);
    }

    hip_set_param_contents_len((struct hip_tlv_common *) &ping, len);
    err = hip_build_generic_param(msg, &ping, sizeof(struct hip_echo_request),
                                  opaque);
    return err;
}

/**
 * build a HIP R1_COUNTER parameter
 *
 * @param msg the message
 * @param generation R1 generation counter
 * @return zero for success, or non-zero on error
 */
int hip_build_param_r1_counter(struct hip_common *msg, uint64_t generation)
{
    struct hip_r1_counter r1gen;
    int err = 0;

    /* note: the length cannot be calculated with calc_param_len() */
    hip_set_param_contents_len((struct hip_tlv_common *) &r1gen,
                               sizeof(struct hip_r1_counter) -
                               sizeof(struct hip_tlv_common));
    /* Type 2 (in R1) or 3 (in I2) */
    hip_set_param_type((struct hip_tlv_common *) &r1gen, HIP_PARAM_R1_COUNTER);

    r1gen.reserved   = 0;

    r1gen.generation = hton64(generation);

    err              = hip_build_param(msg, &r1gen);
    return err;
}

/**
 * Build a @c VIA_RVS parameter to the HIP packet @c msg.
 *
 * @param msg           a pointer to a HIP packet common header
 * @param rvs_addresses a pointer to rendezvous server IPv6 or IPv4-in-IPv6
 *                      format IPv4 addresses.
 * @return              zero on success, or negative error value on error.
 * @see                 <a href="http://tools.ietf.org/wg/hip/draft-ietf-hip-rvs/draft-ietf-hip-rvs-05.txt">
 *                      draft-ietf-hip-rvs-05</a> section 4.2.3.
 */
int hip_build_param_via_rvs(struct hip_common *msg,
                            const struct in6_addr rvs_addresses[])
{
    int err = 0;
    struct hip_via_rvs viarvs;

    hip_set_param_type((struct hip_tlv_common *) &viarvs, HIP_PARAM_VIA_RVS);
    hip_calc_generic_param_len((struct hip_tlv_common *) &viarvs, sizeof(struct hip_via_rvs),
                               sizeof(struct in6_addr));
    err = hip_build_generic_param(msg, &viarvs, sizeof(struct hip_via_rvs),
                                  rvs_addresses);
    return err;
}

/**
 * Builds a @c RELAY_TO parameter to the HIP packet @c msg.
 *
 * @param msg  a pointer to a HIP packet common header
 * @param addr a pointer to IPv6 address
 * @param port portnumber
 * @return     zero on success, or negative error value on error.
 * @note       This used to be VIA_RVS_NAT, but because of the HIP-ICE
 *             draft, this is now RELAY_TO.
 */
int hip_build_param_relay_to(struct hip_common *msg,
                             const struct in6_addr *addr,
                             const in_port_t port)
{
    struct hip_relay_to relay_to;
    int err = 0;

    hip_set_param_type((struct hip_tlv_common *) &relay_to, HIP_PARAM_RELAY_TO);
    ipv6_addr_copy((struct in6_addr *) &relay_to.address, addr);
    relay_to.port     = htons(port);
    relay_to.reserved = 0;
    relay_to.protocol = HIP_NAT_PROTO_UDP;

    hip_calc_generic_param_len((struct hip_tlv_common *) &relay_to, sizeof(relay_to), 0);
    err               = hip_build_param(msg, &relay_to);

    return err;
}

/**
 * Build REG_REQUEST and REG_RESPONSE parameters common parts. This function is
 * called from hip_build_param_reg_request() and hip_build_param_reg_response(),
 * and should not be called from anywhere else.
 *
 * @param msg        a pointer to a HIP message where to build the parameter.
 * @param param      a pointer to the parameter to be appended to the HIP
 *                   message @c msg.
 * @param lifetime   the lifetime to be put into the parameter.
 * @param type_list  a pointer to an array containing the registration types to
 *                   be put into the parameter.
 * @param type_count number of registration types in @c type_list.
 * @return           zero on success, non-zero otherwise.
 * @note             This is an static inline function that has no prototype in
 *                   the header file. There is no prototype because this
 *                   function is not to be called outside this file.
 * @note Keep this function before REG_REQUEST and REG_RESPONSE parameter
 * builders but after hip_calc_generic_param_len() and
 * hip_build_generic_param.
 */
static inline int hip_reg_param_core(struct hip_common *msg,
                                     void *param,
                                     const uint8_t lifetime,
                                     const uint8_t *type_list,
                                     const int type_count)
{
    struct hip_reg_request *rreq = param;

    hip_calc_generic_param_len((struct hip_tlv_common *) rreq, sizeof(struct hip_reg_request),
                               type_count * sizeof(uint8_t));
    rreq->lifetime = lifetime;

    return hip_build_generic_param(msg, rreq, sizeof(struct hip_reg_request),
                                   type_list);
}

/**
 * Build a REG_INFO parameter.
 *
 * @param msg           a pointer to a HIP message where to build the parameter.
 * @param srv_list  a pointer to a structure containing all active services.
 * @param service_count number of registration services in @c service_list.
 * @return              zero on success, non-zero otherwise.
 * @todo gcc gives a weird warning if we use struct srv in the arguments of this function.
 *       Using void pointer as a workaround */
int hip_build_param_reg_info(struct hip_common *msg,
                             const void *srv_list,
                             const unsigned int service_count)
{
    int err    = 0;
    unsigned i = 0;
    const struct hip_srv *service_list = srv_list;
    struct hip_reg_info reg_info;
    uint8_t reg_type[service_count];

    if (service_count == 0) {
        return 0;
    }
    HIP_DEBUG("Building REG_INFO parameter(s) \n");

    for (; i < service_count; i++) {
        if (service_list[0].min_lifetime !=
            service_list[i].min_lifetime ||
            service_list[0].max_lifetime !=
            service_list[i].max_lifetime) {
            HIP_INFO("Warning! Multiple min and max lifetime " \
                     "values for a single REG_INFO parameter " \
                     "requested. Using lifetime values from " \
                     "service reg_type %d with all services.\n",
                     service_list[0].reg_type);
            break;
        }
    }

    for (i = 0; i < service_count; i++) {
        reg_type[i] = service_list[i].reg_type;
    }

    hip_set_param_type((struct hip_tlv_common *) &reg_info, HIP_PARAM_REG_INFO);
    /* All services should have the same lifetime... */
    reg_info.min_lifetime = service_list[0].min_lifetime;
    reg_info.max_lifetime = service_list[0].max_lifetime;
    hip_calc_generic_param_len((struct hip_tlv_common *) &reg_info, sizeof(struct hip_reg_info),
                               service_count * sizeof(service_list[0].reg_type));

    err = hip_build_generic_param(msg, &reg_info, sizeof(struct hip_reg_info),
                                  reg_type);

    return err;
}

/**
 * Build a REG_REQUEST parameter.
 *
 * @param msg        a pointer to a HIP message where to build the parameter.
 * @param lifetime   the lifetime to be put into the parameter.
 * @param type_list  a pointer to an array containing the registration types to
 *                   be put into the parameter.
 * @param type_count number of registration types in @c type_list.
 * @return           zero on success, non-zero otherwise.
 */
int hip_build_param_reg_request(struct hip_common *msg, const uint8_t lifetime,
                                const uint8_t *type_list, const int type_count)
{
    int err = 0;
    struct hip_reg_request rreq;

    hip_set_param_type((struct hip_tlv_common *) &rreq, HIP_PARAM_REG_REQUEST);
    err = hip_reg_param_core(msg, &rreq, lifetime, type_list, type_count);

    return err;
}

/**
 * Build a REG_RESPONSE parameter.
 *
 * @param msg        a pointer to a HIP message where to build the parameter.
 * @param lifetime   the lifetime to be put into the parameter.
 * @param type_list  a pointer to an array containing the registration types to
 *                   be put into the parameter.
 * @param type_count number of registration types in @c type_list.
 * @return           zero on success, non-zero otherwise.
 */
int hip_build_param_reg_response(struct hip_common *msg, const uint8_t lifetime,
                                 const uint8_t *type_list, const int type_count)
{
    int err = 0;
    struct hip_reg_response rres;

    hip_set_param_type((struct hip_tlv_common *) &rres, HIP_PARAM_REG_RESPONSE);
    err = hip_reg_param_core(msg, &rres, lifetime, type_list, type_count);

    return err;
}

/**
 * Build a REG_FAILED parameter.
 *
 * @param msg        a pointer to a HIP message where to build the parameter.
 * @param failure_type   the failure type to be put into the parameter.
 * @param type_list  a pointer to an array containing the registration types to
 *                   be put into the parameter.
 * @param type_count number of registration types in @c type_list.
 * @return           zero on success, non-zero otherwise.
 */
int hip_build_param_reg_failed(struct hip_common *msg, uint8_t failure_type,
                               uint8_t *type_list, int type_count)
{
    int err = 0;
    struct hip_reg_failed reg_failed;

    if (type_count == 0) {
        return 0;
    }

    hip_set_param_type((struct hip_tlv_common *) &reg_failed, HIP_PARAM_REG_FAILED);

    reg_failed.failure_type = failure_type;
    hip_calc_generic_param_len((struct hip_tlv_common *) &reg_failed, sizeof(struct hip_reg_failed),
                               type_count * sizeof(type_list[0]));

    err = hip_build_generic_param(msg, &reg_failed,
                                  sizeof(struct hip_reg_failed), type_list);

    HIP_DEBUG("Added REG_FAILED parameter with %u service%s.\n", type_count,
              (type_count > 1) ? "s" : "");

    return err;
}

/**
 * Build and append a HIP puzzle into the message.
 *
 * The puzzle mechanism assumes that every value is in network byte order
 * except for the hip_birthday_cookie.cv union, where the value is in
 * host byte order. This is an exception to the normal builder rules, where
 * input arguments are normally always in host byte order.
 *
 * @param msg the message where the puzzle is to be appended
 * @param val_K the K value for the puzzle
 * @param lifetime lifetime field of the puzzle
 * @param opaque the opaque value for the puzzle
 * @param random_i random I value for the puzzle (in host byte order)
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_puzzle(struct hip_common *msg, uint8_t val_K,
                           uint8_t lifetime, uint32_t opaque, uint64_t random_i)
{
    struct hip_puzzle puzzle;
    int err = 0;

    /* note: the length cannot be calculated with calc_param_len() */
    hip_set_param_contents_len((struct hip_tlv_common *) &puzzle,
                               sizeof(struct hip_puzzle) -
                               sizeof(struct hip_tlv_common));
    /* Type 2 (in R1) or 3 (in I2) */
    hip_set_param_type((struct hip_tlv_common *) &puzzle, HIP_PARAM_PUZZLE);

    /* only the random_j_k is in host byte order */
    puzzle.K         = val_K;
    puzzle.lifetime  = lifetime;
    puzzle.opaque[0] = opaque & 0xFF;
    puzzle.opaque[1] = (opaque & 0xFF00) >> 8;
    puzzle.I         = random_i;

    err = hip_build_generic_param(msg, &puzzle,
                                  sizeof(struct hip_tlv_common),
                                  hip_get_param_contents_direct(&puzzle));
    return err;
}

#ifdef CONFIG_HIP_MIDAUTH
/**
 * Build and append a HIP challenge_request to the message.
 *
 * The puzzle mechanism assumes that every value is in network byte order
 * except for the hip_birthday_cookie.cv union, where the value is in
 * host byte order. This is an exception to the normal builder rules, where
 * input arguments are normally always in host byte order.
 *
 * @param msg the message where the puzzle_m is to be appended
 * @param val_K the K value for the puzzle_m
 * @param lifetime lifetime field of the puzzle_m
 * @param opaque the opaque data filed of the puzzle_m
 * @param opaque_len the length uf the opaque data field
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_challenge_request(struct hip_common *msg,
                                      uint8_t val_K,
                                      uint8_t lifetime,
                                      uint8_t *opaque,
                                      uint8_t opaque_len)
{
    struct hip_challenge_request puzzle;
    int err = 0;

    /* note: the length cannot be calculated with calc_param_len() */
    hip_set_param_contents_len((struct hip_tlv_common *) &puzzle,
                               sizeof(struct hip_challenge_request) -
                               sizeof(struct hip_tlv_common));
    /* Type 2 (in R1) or 3 (in I2) */
    hip_set_param_type((struct hip_tlv_common *) &puzzle,
                       HIP_PARAM_CHALLENGE_REQUEST);

    /* only the random_j_k is in host byte order */
    puzzle.K        = val_K;
    puzzle.lifetime = lifetime;
    memcpy(&puzzle.opaque, opaque, opaque_len);

    err = hip_build_generic_param(msg,
                                  &puzzle,
                                  sizeof(struct hip_tlv_common),
                                  hip_get_param_contents_direct(&puzzle));
    return err;
}


/**
 * Build and append a HIP solution into the message.
 *
 * The puzzle mechanism assumes that every value is in network byte order
 * except for the hip_birthday_cookie.cv union, where the value is in
 * host byte order. This is an exception to the normal builder rules, where
 * input arguments are normally always in host byte order.
 *
 * @param msg the message where the solution is to be appended
 * @param pz values from the corresponding hip_challenge_request copied to the solution
 * @param val_J J value for the solution (in host byte order)
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_challenge_response(struct hip_common *msg,
                                       const struct hip_challenge_request *pz,
                                       uint64_t val_J)
{
    struct hip_challenge_response cookie;
    int err = 0, opaque_len = 0;

    /* note: the length cannot be calculated with calc_param_len() */
    hip_set_param_contents_len((struct hip_tlv_common *) &cookie,
                               sizeof(struct hip_challenge_response) -
                               sizeof(struct hip_tlv_common));
    /* Type 2 (in R1) or 3 (in I2) */
    hip_set_param_type((struct hip_tlv_common *) &cookie, HIP_PARAM_CHALLENGE_RESPONSE);

    cookie.J        = hton64(val_J);
    cookie.K        = pz->K;
    cookie.lifetime = pz->K;
    opaque_len      = (sizeof(pz->opaque) / sizeof(pz->opaque[0]));
    memcpy(&cookie.opaque, pz->opaque, opaque_len);

    err = hip_build_generic_param(msg,
                                  &cookie,
                                  sizeof(struct hip_tlv_common),
                                  hip_get_param_contents_direct(&cookie));
    return err;
}
#endif /* CONFIG_HIP_MIDAUTH */

/**
 * Build and append a HIP solution into the message.
 *
 * The puzzle mechanism assumes that every value is in network byte order
 * except for the hip_birthday_cookie.cv union, where the value is in
 * host byte order. This is an exception to the normal builder rules, where
 * input arguments are normally always in host byte order.
 *
 * @param msg the message where the solution is to be appended
 * @param pz values from the corresponding puzzle copied to the solution
 * @param val_J J value for the solution (in host byte order)
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_solution(struct hip_common *msg,
                             const struct hip_puzzle *pz,
                             uint64_t val_J)
{
    struct hip_solution cookie;
    int err = 0;

    /* note: the length cannot be calculated with calc_param_len() */
    hip_set_param_contents_len((struct hip_tlv_common *) &cookie,
                               sizeof(struct hip_solution) -
                               sizeof(struct hip_tlv_common));
    /* Type 2 (in R1) or 3 (in I2) */
    hip_set_param_type((struct hip_tlv_common *) &cookie, HIP_PARAM_SOLUTION);

    cookie.J        = hton64(val_J);
    memcpy(&cookie.K, &pz->K, 12);     /* copy: K (1), reserved (1),
                                        * opaque (2) and I (8 bytes). */
    cookie.reserved = 0;
    err = hip_build_generic_param(msg,
                                  &cookie,
                                  sizeof(struct hip_tlv_common),
                                  hip_get_param_contents_direct(&cookie));
    return err;
}

/**
 * Fill HIP DH contents (excludes type and length fields) with one or
 * two public values.
 *
 * @param msg the message where the DH parameter will be appended
 * @param group_id1 the group id of the first DH parameter
 *                  as specified in the drafts
 * @param pubkey1 the public key part of the first DH
 * @param pubkey_len1 length of the first public key part
 * @param group_id2 the group id of the second DH parameter,
 *        should be HIP_MAX_DH_GROUP_ID if there is only one DH key
 * @param pubkey2 the public key part of the second DH
 * @param pubkey_len2 length of the second public key part
 * @return zero on success, or non-zero on error
 */
int hip_build_param_diffie_hellman_contents(struct hip_common *msg,
                                            uint8_t group_id1,
                                            void *pubkey1,
                                            hip_tlv_len_t pubkey_len1,
                                            uint8_t group_id2,
                                            void *pubkey2,
                                            hip_tlv_len_t pubkey_len2)
{
    int err                  = 0;
    struct hip_diffie_hellman diffie_hellman;
    uint8_t *value           = NULL, *value_tmp = NULL;
    hip_tlv_len_t pubkey_len = pubkey_len1 + sizeof(uint8_t) +
                               sizeof(uint16_t) + pubkey_len2;
    uint16_t tmp_pubkey_len2 = 0;


    HIP_ASSERT(pubkey_len >= sizeof(struct hip_tlv_common));

    hip_set_param_type((struct hip_tlv_common *) &diffie_hellman, HIP_PARAM_DIFFIE_HELLMAN);

    if (group_id2 != HIP_MAX_DH_GROUP_ID) {
        pubkey_len = pubkey_len1 + sizeof(uint8_t) +
                     sizeof(uint16_t) + pubkey_len2;
    } else {
        pubkey_len = pubkey_len1;
    }

    /* Allocating memory for the "value" packet */
    HIP_IFEL(!(value = value_tmp = malloc((pubkey_len))),
             -1, "Failed to alloc memory for value\n");

    hip_calc_generic_param_len((struct hip_tlv_common *) &diffie_hellman,
                               sizeof(struct hip_diffie_hellman),
                               pubkey_len);
    diffie_hellman.pub_val.group_id = group_id1;     /* 1 byte, no htons() */
    diffie_hellman.pub_val.pub_len  = htons(pubkey_len1);

    if (group_id2 != HIP_MAX_DH_GROUP_ID) {
        /* Creating "value" by joining the first and second DH values */
        HIP_DEBUG("group_id2 = %d, htons(pubkey_len2)= %d\n",
                  group_id2, htons(pubkey_len2));

        memcpy(value_tmp, pubkey1, pubkey_len1);
        value_tmp      += pubkey_len1;
        *value_tmp++    = group_id2;
        tmp_pubkey_len2 = htons(pubkey_len2);
        memcpy(value_tmp, &tmp_pubkey_len2, sizeof(uint16_t));
        value_tmp      += sizeof(uint16_t);
        memcpy(value_tmp, pubkey2, pubkey_len2);
    } else {
        memcpy(value_tmp, pubkey1, pubkey_len1);
    }

    err = hip_build_generic_param(msg, &diffie_hellman,
                                  sizeof(struct hip_diffie_hellman),
                                  value);

out_err:
    free(value);
    return err;
}

/**
 * Find out the maximum number of transform suite ids
 *
 * @param transform_type the type of the transform
 * @return the number of suite ids that can be used for transform_type
 */
static uint16_t hip_get_transform_max(hip_tlv_type_t transform_type)
{
    uint16_t transform_max = 0;

    switch (transform_type) {
    case HIP_PARAM_HIP_TRANSFORM:
        transform_max = HIP_TRANSFORM_HIP_MAX;
        break;
    case HIP_PARAM_ESP_TRANSFORM:
        transform_max = HIP_TRANSFORM_ESP_MAX;
        break;
    default:
        HIP_ERROR("Unknown transform type %d\n", transform_type);
    }

    return transform_max;
}

/**
 * Build an ESP transform parameter
 *
 * @param msg the message where the parameter will be appended
 * @param transform_suite an array of transform suite ids in host byte order
 * @param transform_count number of transform suites in transform_suite (in host
 *                        byte order)
 *
 * @return zero on success, or negative on error
 */
int hip_build_param_esp_transform(struct hip_common *msg,
                                  const hip_transform_suite_t transform_suite[],
                                  const uint16_t transform_count)
{
    int err = 0;
    uint16_t i;
    uint16_t transform_max;
    struct hip_esp_transform transform_param;

    transform_max = hip_get_transform_max(HIP_PARAM_ESP_TRANSFORM);

    /* Check that the maximum number of transforms is not overflowed */
    if (transform_max > 0 && transform_count > transform_max) {
        err = -E2BIG;
        HIP_ERROR("Too many transforms (%d) for type %d.\n",
                  transform_count, HIP_PARAM_ESP_TRANSFORM);
        goto out_err;
    }

    transform_param.reserved = 0;

    /* Copy and convert transforms to network byte order. */
    for (i = 0; i < transform_count; i++) {
        transform_param.suite_id[i] = htons(transform_suite[i]);
    }

    hip_set_param_type((struct hip_tlv_common *) &transform_param,
                       HIP_PARAM_ESP_TRANSFORM);
    hip_calc_param_len((struct hip_tlv_common *) &transform_param,
                       2 + transform_count * sizeof(hip_transform_suite_t));
    err = hip_build_param(msg, &transform_param);

out_err:
    return err;
}

/**
 * build a HIP transform parameter
 *
 * @param msg the message where the parameter will be appended
 * @param transform_suite an array of transform suite ids in host byte order
 * @param transform_count number of transform suites in transform_suite (in host
 *                        byte order)
 * @return zero on success, or negative on error
 */
int hip_build_param_hip_transform(struct hip_common *msg,
                                  const hip_transform_suite_t transform_suite[],
                                  const uint16_t transform_count)
{
    int err = 0;
    uint16_t i;
    uint16_t transform_max;
    struct hip_hip_transform transform_param;

    transform_max = hip_get_transform_max(HIP_PARAM_HIP_TRANSFORM);


    /* Check that the maximum number of transforms is not overflowed */
    if (transform_max > 0 && transform_count > transform_max) {
        err = -E2BIG;
        HIP_ERROR("Too many transforms (%d) for type %d.\n",
                  transform_count, HIP_PARAM_HIP_TRANSFORM);
        goto out_err;
    }


    /* Copy and convert transforms to network byte order. */
    for (i = 0; i < transform_count; i++) {
        transform_param.suite_id[i] = htons(transform_suite[i]);
    }

    hip_set_param_type((struct hip_tlv_common *) &transform_param,
                       HIP_PARAM_HIP_TRANSFORM);
    hip_calc_param_len((struct hip_tlv_common *) &transform_param,
                       transform_count * sizeof(hip_transform_suite_t));
    err = hip_build_param(msg, &transform_param);

out_err:
    return err;
}

/**
 * retrieve a suite id from a transform structure.
 *
 * @param transform_tlv a pointer to a transform structure
 * @return              the suite id on transform_tlv on index
 * @todo                Remove index and rename.
 */
hip_transform_suite_t hip_get_param_transform_suite_id(const void *transform_tlv)
{
    /** @todo Why do we have hip_select_esp_transform separately? */

    /* RFC 5201 chapter 6.9.:
     * The I2 MUST have a single value in the HIP_TRANSFORM parameter,
     * which MUST match one of the values offered to the Initiator in
     * the R1 packet. Does this function check this?
     * -Lauri 01.08.2008. */
    hip_tlv_type_t type;
    uint16_t supported_hip_tf[] = { HIP_HIP_NULL_SHA1,
                                    HIP_HIP_3DES_SHA1,
                                    HIP_HIP_AES_SHA1};
    uint16_t supported_esp_tf[] = { HIP_ESP_NULL_SHA1,
                                    HIP_ESP_3DES_SHA1,
                                    HIP_ESP_AES_SHA1 };
    const uint16_t *table       = NULL;
    const uint16_t *tfm;
    int table_n                 = 0, pkt_tfms = 0, i;

    type = hip_get_param_type(transform_tlv);
    if (type == HIP_PARAM_HIP_TRANSFORM) {
        table    = supported_hip_tf;
        table_n  = sizeof(supported_hip_tf) / sizeof(uint16_t);
        tfm      = (const uint16_t*) ((const uint8_t *) transform_tlv + sizeof(struct hip_tlv_common));
        pkt_tfms = hip_get_param_contents_len(transform_tlv) / sizeof(uint16_t);
    } else if (type == HIP_PARAM_ESP_TRANSFORM) {
        table    = supported_esp_tf;
        table_n  = sizeof(supported_esp_tf) / sizeof(uint16_t);
        tfm      = (const uint16_t*) ((const uint8_t *) transform_tlv +
                   sizeof(struct hip_tlv_common) + sizeof(uint16_t));
        pkt_tfms = (hip_get_param_contents_len(transform_tlv) - sizeof(uint16_t)) / sizeof(uint16_t);
    } else {
        HIP_ERROR("Invalid type %u\n", type);
        return 0;
    }

    for (i = 0; i < pkt_tfms; i++, tfm++) {
        int j;
        for (j = 0; j < table_n; j++) {
            if (ntohs(*tfm) == table[j]) {
                return table[j];
            }
        }
    }
    HIP_ERROR("Usable suite not found.\n");

    return 0;
}

/**
 * build and append a ESP PROT transform parameter
 *
 * @param msg the message where the parameter will be appended
 * @param transforms the transforms to be used for the esp extension header
 * @param num_transforms the number of transforms
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_esp_prot_transform(struct hip_common *msg,
                                       int num_transforms,
                                       uint8_t *transforms)
{
    struct esp_prot_preferred_tfms prot_transforms;
    int err = 0, i;

    hip_set_param_type((struct hip_tlv_common *) &prot_transforms,
                       HIP_PARAM_ESP_PROT_TRANSFORMS);

    /* note: the length cannot be calculated with calc_param_len() */
    hip_set_param_contents_len((struct hip_tlv_common *) &prot_transforms,
                               (num_transforms + 1) * sizeof(uint8_t));

    prot_transforms.num_transforms = num_transforms;
    HIP_DEBUG("added num_transforms: %u\n", prot_transforms.num_transforms);

    for (i = 0; i < prot_transforms.num_transforms; i++) {
        prot_transforms.transforms[i] = transforms[i];
        HIP_DEBUG("added transform %i: %u\n", i + 1, transforms[i]);
    }

    err = hip_build_generic_param(msg,
                                  &prot_transforms,
                                  sizeof(struct hip_tlv_common),
                                  hip_get_param_contents_direct(&prot_transforms));
    return err;
}

/**
 * build and append am ESP PROT anchor parameter
 *
 * @param msg the message where the parameter will be appended
 * @param transform the esp protection transform used for this anchor,
 *        if UNUSED 1 byte of 0 is sent
 * @param active_anchor the anchor for the hchain to be used for extended esp protection,
 *        if NULL
 * @param next_anchor the next anchor
 * @param hash_length the length of the hash
 * @param hash_item_length the length of the hash item
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_esp_prot_anchor(struct hip_common *msg,
                                    uint8_t transform,
                                    unsigned char *active_anchor,
                                    unsigned char *next_anchor,
                                    int hash_length,
                                    int hash_item_length)
{
    int err = 0;
    struct esp_prot_anchor esp_anchor;

    HIP_ASSERT(msg != NULL);
    /* NULL-active_anchor only allowed for UNUSED-transform */
    HIP_ASSERT((!transform && !active_anchor) || (transform && active_anchor));
    /* next_anchor might be NULL */

    /* set parameter type */
    hip_set_param_type((struct hip_tlv_common *) &esp_anchor, HIP_PARAM_ESP_PROT_ANCHOR);

    /* set parameter values */
    esp_anchor.transform        = transform;
    esp_anchor.hash_item_length = htonl(hash_item_length);

    /* distinguish UNUSED from any other case */
    if (!transform) {
        /* send 1 byte of 0 per anchor in UNUSED case */
        hash_length = 1;

        memset(&esp_anchor.anchors[0], 0, hash_length);
        memset(&esp_anchor.anchors[hash_length], 0, hash_length);
    } else {
        memcpy(&esp_anchor.anchors[0], active_anchor, hash_length);

        /* send 0 if next_anchor not present */
        if (next_anchor) {
            memcpy(&esp_anchor.anchors[hash_length], next_anchor, hash_length);
        } else {
            memset(&esp_anchor.anchors[hash_length], 0, hash_length);
        }
    }

    hip_set_param_contents_len((struct hip_tlv_common *) &esp_anchor,
                               sizeof(uint8_t) + sizeof(uint32_t) + 2
                                       * hash_length);

    err = hip_build_generic_param(msg,
                                  &esp_anchor,
                                  sizeof(struct hip_tlv_common),
                                  hip_get_param_contents_direct(&esp_anchor));

    HIP_DEBUG("added esp protection transform: %u\n", transform);
    HIP_DEBUG("added hash item length: %u\n", hash_item_length);
    HIP_HEXDUMP("added esp protection active_anchor: ",
                &esp_anchor.anchors[0],
                hash_length);
    HIP_HEXDUMP("added esp protection next_anchor: ",
                &esp_anchor.anchors[hash_length],
                hash_length);

    return err;
}

/**
 * build a branch parameter for the ESP extensions
 *
 * @param msg the message where the parameter is appended
 * @param anchor_offset anchor offset value
 * @param branch_length the length of the branch
 * @param branch_nodes the contents of the parameter
 * @return zero on success or negative on error
 */
int hip_build_param_esp_prot_branch(struct hip_common *msg,
                                    int anchor_offset,
                                    int branch_length,
                                    const unsigned char *branch_nodes)
{
    int err = 0;
    struct esp_prot_branch branch;

    HIP_ASSERT(msg != NULL);
    HIP_ASSERT(anchor_offset >= 0);
    HIP_ASSERT(branch_length > 0);
    HIP_ASSERT(branch_nodes != NULL);

    /* set parameter type */
    hip_set_param_type((struct hip_tlv_common *) &branch, HIP_PARAM_ESP_PROT_BRANCH);

    /* set parameter values */
    branch.anchor_offset = htonl(anchor_offset);
    branch.branch_length = htonl(branch_length);
    memcpy(&branch.branch_nodes[0], branch_nodes, branch_length);

    hip_set_param_contents_len((struct hip_tlv_common *) &branch, 2
            * sizeof(uint32_t) + branch_length);

    err = hip_build_generic_param(msg,
                                  &branch,
                                  sizeof(struct hip_tlv_common),
                                  hip_get_param_contents_direct(&branch));

    HIP_DEBUG("added esp anchor offset: %u\n", branch.anchor_offset);
    HIP_DEBUG("added esp branch length: %u\n", branch.branch_length);
    HIP_HEXDUMP("added esp branch: ", &branch.branch_nodes[0], branch_length);

    return err;
}

/**
 * build a secred parameter for the ESP extensions
 *
 * @param msg the message where the parameter is appended
 * @param secret_length the length of the secret value
 * @param secret the contents of the parameter
 * @return zero on success or negative on error
 */
int hip_build_param_esp_prot_secret(struct hip_common *msg,
                                    int secret_length,
                                    const unsigned char *secret)
{
    int err = 0;
    struct esp_prot_secret esp_secret;

    HIP_ASSERT(msg != NULL);
    HIP_ASSERT(secret_length > 0);
    HIP_ASSERT(secret != NULL);

    /* set parameter type */
    hip_set_param_type((struct hip_tlv_common *) &esp_secret, HIP_PARAM_ESP_PROT_SECRET);

    /* set parameter values */
    esp_secret.secret_length = secret_length;
    memcpy(&esp_secret.secret[0], secret, secret_length);

    hip_set_param_contents_len((struct hip_tlv_common *) &esp_secret,
                               sizeof(uint8_t) + secret_length);

    err = hip_build_generic_param(msg, &esp_secret,
                                  sizeof(struct hip_tlv_common),
                                  hip_get_param_contents_direct(&esp_secret));

    HIP_DEBUG("added esp secret length: %u\n", esp_secret.secret_length);
    HIP_HEXDUMP("added esp secret: ", &esp_secret.secret[0], secret_length);

    return err;
}

/**
 * build a root parameter for the ESP extensions
 *
 * @param msg the message where the parameter is appended
 * @param root_length the length of the root value
 * @param root the contents of the parameter
 * @return zero on success or negative on error
 */
int hip_build_param_esp_prot_root(struct hip_common *msg,
                                  uint8_t root_length,
                                  unsigned char *root)
{
    int err = 0;
    struct esp_prot_root esp_root;

    HIP_ASSERT(msg != NULL);
    HIP_ASSERT(root_length > 0);
    HIP_ASSERT(root != NULL);

    // set parameter type
    hip_set_param_type((struct hip_tlv_common *) &esp_root,
                       HIP_PARAM_ESP_PROT_ROOT);

    // set parameter values
    esp_root.root_length = root_length;
    memcpy(&esp_root.root[0], root, root_length);

    hip_set_param_contents_len((struct hip_tlv_common *) &esp_root,
                               sizeof(uint8_t) + root_length);

    err = hip_build_generic_param(msg,
                                  &esp_root,
                                  sizeof(struct hip_tlv_common),
                                  hip_get_param_contents_direct(&esp_root));

    HIP_DEBUG("added esp root length: %u\n", esp_root.root_length);
    HIP_HEXDUMP("added esp root: ", &esp_root.root[0], root_length);

    return err;
}

/**
 * hip_build_param_esp_info - build esp_info parameter
 * @todo Properly comment parameters of hip_build_param_esp_info()
 *
 * @param msg the message where the parameter will be appended
 * @param keymat_index no desription
 * @param old_spi no description
 * @param new_spi no description
 *
 * @return zero on success, or negative on failure
 */
int hip_build_param_esp_info(struct hip_common *msg,
                             uint16_t keymat_index,
                             uint32_t old_spi,
                             uint32_t new_spi)
{
    int err = 0;
    struct hip_esp_info esp_info;

    hip_set_param_type((struct hip_tlv_common *) &esp_info, HIP_PARAM_ESP_INFO);

    hip_calc_generic_param_len((struct hip_tlv_common *) &esp_info,
                               sizeof(struct hip_esp_info),
                               0);

    esp_info.reserved = htonl(0);
    esp_info.keymat_index = htons(keymat_index);
    esp_info.old_spi = htonl(old_spi);
    esp_info.new_spi = htonl(new_spi);

    err = hip_build_param(msg, &esp_info);
    return err;
}

/**
 * build a hip_encrypted parameter
 *
 * @param msg the message where the parameter will be appended
 * @param param the parameter that will contained in the hip_encrypted
 *           parameter
 * @return zero on success, or negative on failure
 * @note that this function does not actually encrypt anything, it just builds
 * the parameter. The parameter that will be encapsulated in the hip_encrypted
 * parameter has to be encrypted using a different function call.
 *
 */
int hip_build_param_encrypted_3des_sha1(struct hip_common *msg,
                                        struct hip_tlv_common *param)
{
    int err = 0;
    struct hip_encrypted_3des_sha1 enc;

    hip_set_param_type((struct hip_tlv_common *) &enc, HIP_PARAM_ENCRYPTED);
    hip_calc_param_len((struct hip_tlv_common *) &enc, sizeof(enc) -
                       sizeof(struct hip_tlv_common) +
                       hip_get_param_total_len(param));
    enc.reserved = htonl(0);
    memset(&enc.iv, 0, 8);

    /* copy the IV *IF* needed, and then the encrypted data */

    err = hip_build_generic_param(msg, &enc, sizeof(enc), param);

    return err;
}

/**
 * build a hip_encrypted parameter
 *
 * @param msg the message where the parameter will be appended
 * @param param the parameter that will contained in the hip_encrypted
 *           parameter
 * @return zero on success, or negative on failure
 * @note this function does not actually encrypt anything, it just builds
 * the parameter. The parameter that will be encapsulated in the hip_encrypted
 * parameter has to be encrypted using a different function call.
 */
int hip_build_param_encrypted_null_sha1(struct hip_common *msg,
                                        struct hip_tlv_common *param)
{
    int err = 0;
    struct hip_encrypted_null_sha1 enc;

    hip_set_param_type((struct hip_tlv_common *) &enc, HIP_PARAM_ENCRYPTED);
    hip_calc_param_len((struct hip_tlv_common *) &enc, sizeof(enc) -
                       sizeof(struct hip_tlv_common) +
                       hip_get_param_total_len(param));
    enc.reserved = htonl(0);

    /* copy the IV *IF* needed, and then the encrypted data */

    err          = hip_build_generic_param(msg, &enc, sizeof(enc), param);

    return err;
}

/**
 * Convert a host id parameter from its compressed on the wire format to
 * the uncompressed internal format.
 *
 * @param wire_host_id the host id parameter
 * @param peer_host_id pointer to memory, where the uncompressed host id is written to
 *
 * @return 0 on success, negative on error (if parameter was of wrong type)
 */
int hip_build_host_id_from_param(const struct hip_host_id *wire_host_id,
                                 struct hip_host_id *peer_host_id)
{
    int err = 0;
    uint16_t header_len;
    uint16_t key_len;
    uint16_t fqdn_len;
    HIP_IFEL(!(hip_get_param_type(wire_host_id) == HIP_PARAM_HOST_ID),
             -1, "Param has wrong type (not HIP_PARAM_HOST_ID)");

    // copy the header, key and fqdn
    header_len  = sizeof(struct hip_host_id) -
                  sizeof(peer_host_id->key) -
                  sizeof(peer_host_id->hostname);
    fqdn_len    = ntohs(wire_host_id->di_type_length) & 0x0FFF;
    key_len     = ntohs(wire_host_id->hi_length) -
                  sizeof(struct hip_host_id_key_rdata);
    memcpy(peer_host_id, wire_host_id, header_len);
    memcpy(peer_host_id->key, wire_host_id->key, key_len);
    memcpy(peer_host_id->hostname, &wire_host_id->key[key_len], fqdn_len);

    // with the header we also copied the compressed length value, so correct this
    hip_set_param_contents_len((struct hip_tlv_common *) peer_host_id,
                               sizeof(struct hip_host_id) -
                               sizeof(struct hip_tlv_common));

out_err:
    return err;
}

/**
 * Build a host id parameter and insert it into a message.
 *
 * @param msg the message where the parameter is inserted
 * @param host_id the host identity from which the parameter is built
 *
 * @return zero on success, negative on error value on error
 * @see hip_build_param()
 */
int hip_build_param_host_id(struct hip_common *msg,
                            const struct hip_host_id *host_id)
{
    struct hip_host_id new_host_id;
    uint16_t header_len;
    uint16_t fqdn_len;
    uint16_t key_len;
    uint16_t par_len;

    // eliminate unused space by copying fqdn directly behind the keyrr
    header_len  = sizeof(struct hip_host_id) -
                  sizeof(host_id->key) -
                  sizeof(host_id->hostname);
    fqdn_len    = ntohs(host_id->di_type_length) & 0x0FFF;
    key_len     = ntohs(host_id->hi_length) -
                  sizeof(struct hip_host_id_key_rdata);
    memcpy(&new_host_id, host_id, header_len);
    memcpy(&new_host_id.key[0], host_id->key, key_len);
    memcpy(&new_host_id.key[key_len], host_id->hostname, fqdn_len);

    // set the new contents length
    // = | length fields | + | keyrr header | + | HI | + | FQDN |
    par_len = header_len + key_len + fqdn_len;
    hip_set_param_contents_len((struct hip_tlv_common *) &new_host_id,
                               par_len - sizeof(struct hip_tlv_common));

    return hip_build_param(msg, &new_host_id);
}

/**
 * build the header of a host id parameter
 *
 * @param host_id_hdr the header
 * @param hostname a string containing a hostname or NAI (URI)
 * @param rr_data_len the length of the DNS RR field to be appended separately into
 *                    the message
 * @param algorithm the public key algorithm
 */
void hip_build_param_host_id_hdr(struct hip_host_id *host_id_hdr,
                                 const char *hostname,
                                 hip_tlv_len_t rr_data_len,
                                 uint8_t algorithm)
{
    uint16_t hi_len = sizeof(struct hip_host_id_key_rdata) + rr_data_len;
    uint16_t fqdn_len;
    /* reserve 1 byte for NULL termination */
    if (hostname) {
        fqdn_len = (strlen(hostname) + 1) & 0x0FFF;
    } else {
        fqdn_len = 0;
    }

    host_id_hdr->hi_length      = htons(hi_len);
    /* length = 12 bits, di_type = 4 bits */
    host_id_hdr->di_type_length = htons(fqdn_len | 0x1000);
    /* if the length is 0, then the type should also be zero */
    if (host_id_hdr->di_type_length == ntohs(0x1000)) {
        host_id_hdr->di_type_length = 0;
    }

    hip_set_param_type((struct hip_tlv_common *) host_id_hdr, HIP_PARAM_HOST_ID);
    hip_calc_generic_param_len((struct hip_tlv_common *) host_id_hdr,
                               sizeof(struct hip_host_id),
                               0);

    host_id_hdr->rdata.flags     = htons(0x0202); /* key is for a host */

    /* RFC 4034 obsoletes RFC 2535 and flags field differ */
    host_id_hdr->rdata.protocol  = 0xFF;    /* RFC 2535 */
    /* algo is 8 bits, no htons */
    host_id_hdr->rdata.algorithm = algorithm;
}

/**
 * build a host id parameter containing a public key for on-the-wire
 * transmission
 *
 * @param host_id a hip_host_id structure (public key)
 * @param fqdn a string containing a hostname or NAI (URI)
 * @param rr_data the length of the DNS RR field to be appended separately into
 *                    the message
 */
void hip_build_param_host_id_only(struct hip_host_id *host_id,
                                  const void *rr_data,
                                  const char *fqdn)
{
    unsigned int rr_len = ntohs(host_id->hi_length) -
                          sizeof(struct hip_host_id_key_rdata);
    uint16_t fqdn_len;

    memcpy(host_id->key, rr_data, rr_len);

    fqdn_len = ntohs(host_id->di_type_length) & 0x0FFF;
    if (fqdn_len) {
        memcpy(host_id->hostname, fqdn, fqdn_len);
    }
}

/**
 * Build a header for a host id parameter containing a private key. Used
 * by hipconf to transport new host identities to hipd.
 *
 * @param host_id_hdr a hip_host_id_priv structure
 * @param hostname a string containing a hostname or NAI (URI)
 * @param rr_data_len the length of the DNS RR field to be appended separately into
 *                    the message
 * @param algorithm the public key algorithm
 */
static void hip_build_param_host_id_hdr_priv(struct hip_host_id_priv *host_id_hdr,
                                             const char *hostname,
                                             hip_tlv_len_t rr_data_len,
                                             uint8_t algorithm)
{
    uint16_t hi_len = sizeof(struct hip_host_id_key_rdata) + rr_data_len;
    uint16_t fqdn_len;
    /* reserve 1 byte for NULL termination */
    if (hostname) {
        fqdn_len = (strlen(hostname) + 1) & 0x0FFF;
    } else {
        fqdn_len = 0;
    }

    host_id_hdr->hi_length      = htons(hi_len);
    /* length = 12 bits, di_type = 4 bits */
    host_id_hdr->di_type_length = htons(fqdn_len | 0x1000);
    /* if the length is 0, then the type should also be zero */
    if (host_id_hdr->di_type_length == ntohs(0x1000)) {
        host_id_hdr->di_type_length = 0;
    }

    hip_set_param_type((struct hip_tlv_common *) host_id_hdr, HIP_PARAM_HOST_ID);
    hip_calc_generic_param_len((struct hip_tlv_common *) host_id_hdr,
                               sizeof(struct hip_host_id_priv),
                               0);

    host_id_hdr->rdata.flags     = htons(0x0202); /* key is for a host */

    /* RFC 4034 obsoletes RFC 2535 and flags field differ */
    host_id_hdr->rdata.protocol  = 0xFF;    /* RFC 2535 */
    /* algo is 8 bits, no htons */
    host_id_hdr->rdata.algorithm = algorithm;
}

/**
 * retrieve the type and length of a hostname inside a host id parameter
 *
 * @param host host_id parameter
 * @param id output argument that points to a human readable string
 *           that tells the type of hostname (statically allocated)
 * @param len the length of the hostname in bytes
 * @return zero on success and negative on error
 */
int hip_get_param_host_id_di_type_len(const struct hip_host_id *host,
                                      const char **id,
                                      int *len)
{
    int type;
    static const char *debuglist[3] = {"none", "FQDN", "NAI"};

    type = ntohs(host->di_type_length);
    *len = type & 0x0FFF;
    type = (type & 0xF000) >> 12;

    if (type > 2) {
        HIP_ERROR("Illegal DI-type: %d\n", type);
        return -1;
    }

    *id = debuglist[type];
    return 0;
}

/**
 * an accessor function to retrive a pointer to the hostname field within
 * a host id parameter
 *
 * @param hostid the host id parameter
 * @return a pointer to the hostname field
 */
const char *hip_get_param_host_id_hostname(const struct hip_host_id *hostid)
{
    return hostid->hostname;
}

/**
 * Fill in an endpoint header that can contain a DSA or RSA key in HIP
 * RR format. This is used for sending new private keys to hipd
 * using hipconf.
 *
 * @param endpoint_hdr the endpoint header that should be filled in
 * @param hostname an optional hostname to be written into the endpoint
 * @param endpoint_flags flags for the endpoint
 * @param host_id_algo the public key algorithm
 * @param rr_data_len length of the HIP Resource Record that will be
 *                    appended after the header later.
 *
 * @note: @c endpoint_hip structure is not padded because it is not
 *           sent on wire
 */
static void hip_build_endpoint_hdr(struct endpoint_hip *endpoint_hdr,
                                   const char *hostname,
                                   se_hip_flags_t endpoint_flags,
                                   uint8_t host_id_algo,
                                   unsigned int rr_data_len)
{
    hip_build_param_host_id_hdr_priv(&endpoint_hdr->id.host_id,
                                     hostname, rr_data_len, host_id_algo);
    endpoint_hdr->family = PF_HIP;
    endpoint_hdr->length = sizeof(struct endpoint_hip);
    endpoint_hdr->flags  = endpoint_flags;
    endpoint_hdr->algo   = host_id_algo;
}

/**
 * append an endpoint structure into a message
 *
 * @param msg the endpoint structure will be appended here
 * @param endpoint the endpoint structure
 * @return zero on success and negative on failure
 */
static int hip_build_param_eid_endpoint_from_host_id(struct hip_common *msg,
                                                     const struct endpoint_hip *endpoint)
{
    int err = 0;

    HIP_ASSERT(!(endpoint->flags & HIP_ENDPOINT_FLAG_HIT));

    err = hip_build_param_contents(msg, endpoint, HIP_PARAM_EID_ENDPOINT,
                                   endpoint->length);
    return err;
}

/**
 * Append an endpoint structure containing a HIT to the given message
 * (interprocess communications only).
 *
 * @param msg the endpoint structure will be appended here
 * @param endpoint an endpoint structure containing a HIT
 * @return zero on success and negative on failure
 */
static int hip_build_param_eid_endpoint_from_hit(struct hip_common *msg,
                                                 const struct endpoint_hip *endpoint)
{
    struct hip_eid_endpoint eid_endpoint;
    int err = 0;

    HIP_ASSERT(endpoint->flags & HIP_ENDPOINT_FLAG_HIT);

    hip_set_param_type((struct hip_tlv_common *) &eid_endpoint, HIP_PARAM_EID_ENDPOINT);

    hip_calc_param_len((struct hip_tlv_common *) &eid_endpoint,
                       sizeof(struct hip_eid_endpoint) -
                       sizeof(struct hip_tlv_common));

    memcpy(&eid_endpoint.endpoint, endpoint, sizeof(struct endpoint_hip));

    err = hip_build_param(msg, &eid_endpoint);

    return err;
}

/**
 * Build an endpoint parameter.
 *
 * Hipconf uses this to pass host identifiers to hipd. The endpoint is
 * wrapped into an eid endpoint structure because endpoint_hip is not
 * padded. However, all parameters need to be padded in the builder
 * interface.
 *
 * @param msg the message where the eid endpoint parameter will be appended
 * @param endpoint the endpoint to be wrapped into the eid endpoint structure
 * @return zero on success and negative on failure
 * @note the EID stands for Endpoint IDentifier
 */
int hip_build_param_eid_endpoint(struct hip_common *msg,
                                 const struct endpoint_hip *endpoint)
{
    int err = 0;

    if (endpoint->flags & HIP_ENDPOINT_FLAG_HIT) {
        err = hip_build_param_eid_endpoint_from_hit(msg, endpoint);
    } else {
        err = hip_build_param_eid_endpoint_from_host_id(msg, endpoint);
    }

    return err;
}

/**
 * Build a CERT parameter
 *
 * The CERT parameter is a container for X.509.v3 certificates and for
 * Simple Public Key Infrastructure (SPKI) certificates.  It is used for
 * carrying these certificates in HIP control packets.
 * See draft-ietf-hip-cert for more information.
 *
 * @param msg the message where the CERT parameter will be appended.
 * @param group Group ID grouping multiple related CERT parameters.
 * @param count Total count of certificates that are sent.
 * @param id The sequence number for this certificate.
 * @param type Describes the type of the certificate.
 * @param data The certificate
 * @param size the length of @c data in bytes
 * @return zero on success or negative on failure
 */
int hip_build_param_cert(struct hip_common *msg, uint8_t group, uint8_t count,
                         uint8_t id, uint8_t type, void *data, size_t size)
{
    struct hip_cert cert;
    int err;

    hip_set_param_type((struct hip_tlv_common *) &cert, HIP_PARAM_CERT);
    hip_calc_param_len((struct hip_tlv_common *) &cert, sizeof(struct hip_cert) -
                       sizeof(struct hip_tlv_common) + size);
    cert.cert_group = group;
    cert.cert_count = count;
    cert.cert_id    = id;
    cert.cert_type  = type;

    err = hip_build_generic_param(msg, &cert, sizeof(struct hip_cert), data);
    return err;
}

/**
 * Append heartbeat interval value to a message. Interprocess
 * communications only.
 *
 * @param msg     a pointer to the message where the parameter will be
 *                appended
 * @param seconds set the heartbeat interval to this value
 * @return zero on success, or negative on failure
 *
 */
int hip_build_param_heartbeat(struct hip_common *msg, int seconds)
{
    int err = 0;
    struct hip_heartbeat heartbeat;
    hip_set_param_type((struct hip_tlv_common *) &heartbeat,
                       HIP_PARAM_HEARTBEAT);
    hip_calc_param_len((struct hip_tlv_common *) &heartbeat,
                       sizeof(struct hip_heartbeat)
                               - sizeof(struct hip_tlv_common));
    memcpy(&heartbeat.heartbeat, &seconds, sizeof(seconds));
    err = hip_build_param(msg, &heartbeat);

    return err;
}

/**
 * Append a parameter which defines to preferred order of transforms.
 * Can be used only for interprocess communications.
 *
 * @param msg a pointer to the message where the parameter will be
 *            appended
 * @param order the order of transforms
 * @return zero on success, or negative on failure
 * @see hip_conf_handle_trans_order() and @c HIPL_CONFIG_FILE_EX variable
 *      for the @c order format
 */
int hip_build_param_transform_order(struct hip_common *msg, int order)
{
    int err = 0;
    struct hip_transformation_order transorder;
    hip_set_param_type((struct hip_tlv_common *) &transorder,
                       HIP_PARAM_TRANSFORM_ORDER);
    hip_calc_param_len((struct hip_tlv_common *) &transorder,
                       sizeof(struct hip_transformation_order)
                               - sizeof(struct hip_tlv_common));
    transorder.transorder = order;
    err = hip_build_param(msg, &transorder);
    return err;
}

/**
 * Build and append a SPKI infor parameter into a HIP control message (on-the-wire)
 *
 * @param msg a pointer to the message where the parameter will be
 *            appended
 * @param cert_info certificate information
 * @return zero on success, or negative on failure
 * @see <a href="http://tools.ietf.org/html/draft-ietf-hip-cert">draft-ietf-hip-cert</a>
 *
 */
int hip_build_param_cert_spki_info(struct hip_common *msg,
                                   struct hip_cert_spki_info *cert_info)
{
    int err = 0;
    struct hip_cert_spki_info local;
    memset(&local, '\0', sizeof(struct hip_cert_spki_info));
    memcpy(&local, cert_info, sizeof(struct hip_cert_spki_info));
    hip_set_param_type((struct hip_tlv_common *) &local,
                       HIP_PARAM_CERT_SPKI_INFO);
    hip_calc_param_len((struct hip_tlv_common *) &local,
                       sizeof(struct hip_cert_spki_info)
                               - sizeof(struct hip_tlv_common));
    err = hip_build_param(msg, &local);
    return err;
}

/**
 * Build and append a X509 certiticate request parameter into a HIP control
 * message (on-the-wire)
 *
 * @param msg a pointer to the message where the parameter will be
 *            appended
 * @param addr the subject for the certificate
 * @return zero on success, or negative on failure
 * @see <a href="http://tools.ietf.org/html/draft-ietf-hip-cert">draft-ietf-hip-cert</a>
 *
 */
int hip_build_param_cert_x509_req(struct hip_common *msg, struct in6_addr *addr)
{
    int err = 0;
    struct hip_cert_x509_req subj;

    hip_set_param_type((struct hip_tlv_common *) &subj, HIP_PARAM_CERT_X509_REQ);
    hip_calc_param_len((struct hip_tlv_common *) &subj,
                       sizeof(struct hip_cert_x509_req)
                               - sizeof(struct hip_tlv_common));
    ipv6_addr_copy(&subj.addr, addr);
    err = hip_build_param(msg, &subj);
    return err;
}

/**
 * build and append a X509 certificate verification parameter into a
 * HIP control message (on-the-wire)
 *
 * @param msg a pointer to the message where the parameter will be
 *            appended
 * @param der der field
 * @param len length of the der field in bytes
 * @return zero on success, or negative on failure
 * @see <a href="http://tools.ietf.org/html/draft-ietf-hip-cert">draft-ietf-hip-cert</a>
 *
 */
int hip_build_param_cert_x509_ver(struct hip_common *msg, char *der, int len)
{
    int err = 0;
    struct hip_cert_x509_resp subj;

    hip_set_param_type((struct hip_tlv_common *) &subj, HIP_PARAM_CERT_X509_REQ);
    hip_calc_param_len((struct hip_tlv_common *) &subj,
                       sizeof(struct hip_cert_x509_resp)
                               - sizeof(struct hip_tlv_common));
    memcpy(&subj.der, der, len);
    subj.der_len = len;
    err = hip_build_param(msg, &subj);
    return err;
}

/**
 * build and append a X509 certificate response into a HIP control message
 * (on-the-wire)
 *
 * @param msg a pointer to the message where the parameter will be
 *            appended
 * @param der der field
 * @param len length of the der field in bytes
 * @return zero on success, or negative on failure
 * @see <a href="http://tools.ietf.org/html/draft-ietf-hip-cert">draft-ietf-hip-cert</a>
 *
 */
int hip_build_param_cert_x509_resp(struct hip_common *msg, char *der, int len)
{
    int err = 0;
    struct hip_cert_x509_resp local;
    hip_set_param_type((struct hip_tlv_common *) &local,
                       HIP_PARAM_CERT_X509_RESP);
    hip_calc_param_len((struct hip_tlv_common *) &local,
                       sizeof(struct hip_cert_x509_resp)
                               - sizeof(struct hip_tlv_common));
    memcpy(&local.der, der, len);
    local.der_len = len;
    err           = hip_build_param(msg, &local);
    return err;
}

/**
 * Build an append a zone parameter for hit-to-ip extension.
 *
 * @param msg a pointer to the message where the parameter will be
 *            appended
 * @param name the zone name to change for hit-to-ip
 * @return zero on success, or negative on failure
 */
int hip_build_param_hit_to_ip_set(struct hip_common *msg, const char *name)
{
    int err = 0;
    struct hip_hit_to_ip_set name_info;
    hip_set_param_type((struct hip_tlv_common *) &name_info,
                       HIP_PARAM_HIT_TO_IP_SET);
    hip_calc_param_len((struct hip_tlv_common *) &name_info,
                       sizeof(struct hip_hit_to_ip_set)
                               - sizeof(struct hip_tlv_common));
    strcpy(name_info.name, name);
    err = hip_build_param(msg, &name_info);

    return err;
}

/**
 * Convert a DSA structure from OpenSSL into an endpoint_hip structure
 * used internally by the implementation.
 *
 * @param dsa the DSA key to be converted
 * @param endpoint An output argument. This function allocates and
 *                 stores the result of the conversion here. Caller
 *                 is responsible of deallocation.
 * @param endpoint_flags
 * @param hostname host name for the DSA key
 * @return zero on success and negative on failure
 */
int dsa_to_hip_endpoint(DSA *dsa,
                        struct endpoint_hip **endpoint,
                        se_hip_flags_t endpoint_flags,
                        const char *hostname)
{
    int err = 0;
    unsigned char *dsa_key_rr = NULL;
    int dsa_key_rr_len;
    struct endpoint_hip endpoint_hdr;

    dsa_key_rr_len = dsa_to_dns_key_rr(dsa, &dsa_key_rr);
    if (dsa_key_rr_len <= 0) {
        HIP_ERROR("dsa_key_rr_len <= 0\n");
        err = -ENOMEM;
        goto out_err;
    }

    hip_build_endpoint_hdr(&endpoint_hdr,
                           hostname,
                           endpoint_flags,
                           HIP_HI_DSA,
                           dsa_key_rr_len);

    *endpoint = malloc(endpoint_hdr.length);
    if (!(*endpoint)) {
        err = -ENOMEM;
        goto out_err;
    }
    memset(*endpoint, 0, endpoint_hdr.length);

    hip_build_endpoint(*endpoint,
                       &endpoint_hdr,
                       hostname,
                       dsa_key_rr);

out_err:
    free(dsa_key_rr);
    return err;
}

/**
 * Convert an RSA structure from OpenSSL into an endpoint_hip structure
 * used internally by the implementation.
 *
 * @param rsa the RSA key to be converted
 * @param endpoint An output argument. This function allocates and
 *                 stores the result of the conversion here. Caller
 *                 is responsible of deallocation.
 * @param endpoint_flags The endpoint flags
 * @param hostname host name for the DSA key
 * @return zero on success and negative on failure
 */
int rsa_to_hip_endpoint(RSA *rsa,
                        struct endpoint_hip **endpoint,
                        se_hip_flags_t endpoint_flags,
                        const char *hostname)
{
    int err = 0;
    unsigned char *rsa_key_rr = NULL;
    int rsa_key_rr_len;
    struct endpoint_hip endpoint_hdr;

    HIP_DEBUG("rsa_to_hip_endpoint called\n");

    rsa_key_rr_len = rsa_to_dns_key_rr(rsa, &rsa_key_rr);
    if (rsa_key_rr_len <= 0) {
        HIP_ERROR("rsa_key_rr_len <= 0\n");
        err = -ENOMEM;
        goto out_err;
    }

    hip_build_endpoint_hdr(&endpoint_hdr,
                           hostname,
                           endpoint_flags,
                           HIP_HI_RSA,
                           rsa_key_rr_len);

    *endpoint = malloc(endpoint_hdr.length);
    if (!(*endpoint)) {
        err = -ENOMEM;
        goto out_err;
    }
    memset(*endpoint, 0, endpoint_hdr.length);

    hip_build_endpoint(*endpoint,
                       &endpoint_hdr,
                       hostname,
                       rsa_key_rr);

out_err:
    free(rsa_key_rr);
    return err;
}

/**
 * Translate a host id into a HIT
 *
 * @param any_key a pointer to DSA or RSA key in OpenSSL format
 * @param hit the resulting HIT will be stored here
 * @param is_public 0 if the host id constains the private key
 *                  or 1 otherwise
 * @param is_dsa 1 if the key is DSA or zero for RSA
 * @return zero on success and negative on failure
 */
static int hip_any_key_to_hit(void *any_key,
                              hip_hit_t *hit,
                              int is_public,
                              int is_dsa)
{
    int err = 0, key_rr_len;
    unsigned char *key_rr = NULL;
    char hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
    struct hip_host_id_priv *host_id = NULL;
    struct hip_host_id *host_id_pub = NULL;
    RSA *rsa_key = any_key;
    DSA *dsa_key = any_key;

    memset(hostname, 0, HIP_HOST_ID_HOSTNAME_LEN_MAX);
    HIP_IFEL(gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1), -1,
            "gethostname failed\n");

    if (is_dsa) {
        HIP_IFEL(((key_rr_len = dsa_to_dns_key_rr(dsa_key, &key_rr)) <= 0), -1,
                "key_rr_len\n");
        if (is_public) {
            HIP_IFEL(!(host_id_pub = malloc(sizeof(struct hip_host_id))),
                    -ENOMEM, "malloc\n");
            host_id_pub->hi_length = htons(key_rr_len
                    + sizeof(struct hip_host_id_key_rdata));
            memcpy(&host_id_pub->key, key_rr, key_rr_len);
            HIP_IFEL(hip_dsa_host_id_to_hit(host_id_pub, hit, HIP_HIT_TYPE_HASH100),
                    -1, "conversion from host id to hit failed\n");
        } else {
            HIP_IFEL(!(host_id = malloc(sizeof(struct hip_host_id_priv))),
                    -ENOMEM,
                    "malloc\n");

            host_id->hi_length = htons(key_rr_len
                    + sizeof(struct hip_host_id_key_rdata));
            memcpy(&host_id->key, key_rr, key_rr_len);
            HIP_IFEL(hip_private_dsa_host_id_to_hit(host_id, hit,
                                                    HIP_HIT_TYPE_HASH100),
                     -1, "conversion from host id to hit failed\n");
        }
    } else { /* rsa */
        HIP_IFEL(((key_rr_len = rsa_to_dns_key_rr(rsa_key, &key_rr)) <= 0), -1,
                 "key_rr_len\n");
        if (is_public) {
            HIP_IFEL(!(host_id_pub = malloc(sizeof(struct hip_host_id))),
                     -ENOMEM, "malloc\n");

            host_id_pub->hi_length = htons(key_rr_len +
                                           sizeof(struct hip_host_id_key_rdata));

            memcpy(&host_id_pub->key, key_rr, key_rr_len);

            HIP_IFEL(hip_rsa_host_id_to_hit(host_id_pub,
                                            hit,
                                            HIP_HIT_TYPE_HASH100),
                     -1,
                     "conversion from host id to hit failed\n");
        } else {
            HIP_IFEL(!(host_id = malloc(sizeof(struct hip_host_id_priv))),
                     -ENOMEM,
                     "malloc\n");

            host_id->hi_length = htons(key_rr_len +
                                       sizeof(struct hip_host_id_key_rdata));
            memcpy(&host_id->key, key_rr, key_rr_len);

            HIP_IFEL(hip_private_rsa_host_id_to_hit(host_id,
                                                    hit,
                                                    HIP_HIT_TYPE_HASH100),
                     -1,
                     "conversion from host id to hit failed\n");
        }
    }

    HIP_DEBUG_HIT("hit", hit);
    HIP_DEBUG("hi is %s %s\n", (is_public ? "public" : "private"),
              (is_dsa ? "dsa" : "rsa"));

out_err:
    free(key_rr);
    free(host_id);
    free(host_id_pub);
    return err;
}

/**
 * translate a private RSA key to a HIT
 *
 * @param rsa_key the RSA key in OpenSSL format
 * @param hit the resulting HIT will be stored here
 * @return zero on success and negative on failure
 */
int hip_private_rsa_to_hit(RSA *rsa_key,
                           struct in6_addr *hit)
{
    return hip_any_key_to_hit(rsa_key, hit, 0, 0);
}

/**
 * translate a private DSA key to a HIT
 *
 * @param dsa_key the DSA key in OpenSSL format
 * @param hit the resulting HIT will be stored here
 * @return zero on success and negative on failure
 */
int hip_private_dsa_to_hit(DSA *dsa_key,
                           struct in6_addr *hit)
{
    return hip_any_key_to_hit(dsa_key, hit, 0, 1);
}

/**
 * Build a @c RELAY_TO parameter to the HIP packet @c msg.
 *
 * @param msg  a pointer to a HIP packet common header
 * @param addr a pointer to IPv6 address
 * @param port portnumber
 * @return     zero on success, or negative error value on error.
 * @note       This used to be VIA_RVS_NAT, but because of the HIP-ICE
 *             draft, this is now RELAY_TO.
 */
int hip_build_param_reg_from(struct hip_common *msg,
                             const struct in6_addr *addr,
                             const in_port_t port)
{
    struct hip_reg_from reg_from;
    int err = 0;

    hip_set_param_type((struct hip_tlv_common *) &reg_from, HIP_PARAM_REG_FROM);
    ipv6_addr_copy((struct in6_addr *) &reg_from.address, addr);
    HIP_DEBUG_IN6ADDR("reg_from address is ", &reg_from.address);
    HIP_DEBUG_IN6ADDR("the given address is ", addr);
    reg_from.port     = htons(port);
    reg_from.reserved = 0;
    reg_from.protocol = HIP_NAT_PROTO_UDP;
    hip_calc_generic_param_len((struct hip_tlv_common *) &reg_from, sizeof(reg_from), 0);
    err               = hip_build_param(msg, &reg_from);

    return err;
}

/**
 * Build NAT port parameter
 *
 * @param msg a pointer to a HIP packet common header
 * @param port NAT port number
 * @param hipparam parameter to create. Currently it is either
 *              HIP_SET_SRC_NAT_PORT or HIP_SET_DST_NAT_PORT
 *
 * @return zero on success, non-zero otherwise.
 */
int hip_build_param_nat_port(struct hip_common *msg,
                             const in_port_t port,
                             hip_tlv_type_t hipparam)
{
    int err = 0;
    struct hip_port_info nat_port;

    hip_set_param_type((struct hip_tlv_common *) &nat_port, hipparam);
    nat_port.port = port;
    hip_calc_generic_param_len((struct hip_tlv_common *) &nat_port, sizeof(nat_port), 0);
    err           = hip_build_param(msg, &nat_port);

    return err;
}

/**
 * calculate a digest over given data
 * @param type the type of digest, e.g. "sha1"
 * @param in the beginning of the data to be digested
 * @param in_len the length of data to be digested in octets
 * @param out the digest
 *
 * @note out should be long enough to hold the digest. This cannot be
 * checked!
 *
 * @return 0 on success and negative on error.
 */
int hip_build_digest(const int type, const void *in, int in_len, void *out)
{
    SHA_CTX sha;
    MD5_CTX md5;

    switch (type) {
    case HIP_DIGEST_SHA1:
        SHA1_Init(&sha);
        SHA1_Update(&sha, in, in_len);
        SHA1_Final(out, &sha);
        break;

    case HIP_DIGEST_MD5:
        MD5_Init(&md5);
        MD5_Update(&md5, in, in_len);
        MD5_Final(out, &md5);
        break;

    default:
        HIP_ERROR("Unknown digest: %x\n", type);
        return -EFAULT;
    }

    return 0;
}

/**
 * Build a @c RELAY_FROM parameter to the HIP packet @c msg.
 *
 * @param msg  a pointer to a HIP packet common header
 * @param addr a pointer to an IPv6 or IPv4-in-IPv6 format IPv4 address.
 * @param port port number (host byte order).
 * @return     zero on success, or negative error value on error.
 */
int hip_build_param_relay_from(struct hip_common *msg,
                               const struct in6_addr *addr,
                               const in_port_t port)
{
    struct hip_relay_from relay_from;
    int err = 0;

    hip_set_param_type((struct hip_tlv_common *) &relay_from,
                       HIP_PARAM_RELAY_FROM);
    ipv6_addr_copy((struct in6_addr *) &relay_from.address, addr);
    relay_from.port = htons(port);
    relay_from.reserved = 0;
    relay_from.protocol = HIP_NAT_PROTO_UDP;
    hip_calc_generic_param_len((struct hip_tlv_common *) &relay_from,
                               sizeof(relay_from), 0);
    err = hip_build_param(msg, &relay_from);

    return err;
}

/**
 * Build a @c FROM parameter to the HIP packet @c msg.
 *
 * @param msg      a pointer to a HIP packet common header
 * @param addr     a pointer to an IPv6 or IPv4-in-IPv6 format IPv4 address.
 * @return         zero on success, or negative error value on error.
 * @see            RFC5204 section 4.2.2.
 */
int hip_build_param_from(struct hip_common *msg,
                         const struct in6_addr *addr)
{
    struct hip_from from;
    int err = 0;

    hip_set_param_type((struct hip_tlv_common *) &from, HIP_PARAM_FROM);
    ipv6_addr_copy((struct in6_addr *) &from.address, addr);

    hip_calc_generic_param_len((struct hip_tlv_common *) &from,
                               sizeof(struct hip_from), 0);
    err = hip_build_param(msg, &from);
    return err;
}
