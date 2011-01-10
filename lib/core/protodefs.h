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
 * This file defines a Host Identity Protocol (HIP) header and parameter
 * related constants and structures.
 */

#ifndef HIP_LIB_CORE_PROTODEFS_H
#define HIP_LIB_CORE_PROTODEFS_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "esp_prot_common.h"
#include "hashchain.h"

#ifndef PF_HIP
#  define PF_HIP 32
#endif
#ifndef AF_HIP
#  define AF_HIP 32
#endif

#ifndef IPPROTO_HIP
#  define IPPROTO_HIP             139
#endif

#define IPV4_HDR_SIZE 20

#define HIP_MAX_PACKET 4096
#define HIP_MAX_NETWORK_PACKET 2048

/**
 * @defgroup hip_msg HIP daemon message types
 * @note Don't make these values higher than 255.
 *       The variable, which stores this type, is 8 bits.
 * @{
 */
#define HIP_I1                  1
#define HIP_R1                  2
#define HIP_I2                  3
#define HIP_R2                  4
#define HIP_CER                 5

#define HIP_UPDATE              16
#define HIP_NOTIFY              17
#define HIP_CLOSE               18
#define HIP_CLOSE_ACK           19
/* 20 was already occupied by HIP_PSIG so shifting HIP_PSIG and HIP_TRIG plus 1*/
/* free slot */
#define HIP_PSIG                21 ///< lightweight HIP pre signature
#define HIP_TRIG                22 ///< lightweight HIP signature trigger
#define HIP_LUPDATE             23
#define HIP_DATA                32
#define HIP_PAYLOAD             64
/* only hip network message types here */
/* @} */

/**
 * @todo add description
 */
#define HIP_MAX_PACKET_TYPE      64

#define HIP_HIT_TYPE_HASH100    1
#define HIP_HIT_TYPE_MASK_100   0x20010010
#define HIP_TEREDO_TYPE_MASK_100 0x20010000
#define HIP_LSI_TYPE_MASK_1     0x01000000
#define HIP_HIT_TYPE_MASK_CLEAR 0x0000000f
#define HIP_LSI_TYPE_MASK_CLEAR 0x000000ff
#define HIP_HIT_TYPE_MASK_INV   0xfffffff0
#define HIP_TEREDO_TYPE_MASK_INV 0xffffffff
#define HIP_HIT_PREFIX          HIP_HIT_TYPE_MASK_100
#define HIP_TEREDO_PREFIX       HIP_TEREDO_TYPE_MASK_100
#define HIP_LSI_PREFIX          HIP_LSI_TYPE_MASK_1
#define HIP_HIT_PREFIX_LEN      28      /* bits */
#define HIP_LSI_PREFIX_LEN      24      /* bits */
#define HIP_HIT_FULL_PREFIX_STR "/128"
#define HIP_HIT_PREFIX_STR      "/28"
#define HIP_LSI_FULL_PREFIX_STR "/24"
#define HIP_FULL_LSI_STR        "1.0.0.0/8"
#define HIP_KHI_CONTEXT_ID_INIT { 0xF0, 0xEF, 0xF0, 0x2F, 0xBF, 0xF4, 0x3D, 0x0F, \
                                  0xE7, 0x93, 0x0C, 0x3C, 0x6E, 0x61, 0x74, 0xEA }


/**
 * Type values used in Host Identity Protocol (HIP) parameters.
 *
 * These are the type values used in Host Identity Protocol (HIP) parameters
 * defined in [draft-ietf-hip-base] and other drafts expanding it. Because the
 * ordering (from lowest to highest) of HIP parameters is strictly enforced, the
 * parameter type values for existing parameters have been spaced to allow for
 * future protocol extensions.
 *
 * <b>Type values are grouped as follows:</b>
 * <ul>
 * <li>0-1023 are used in HIP handshake and update procedures and are covered
 * by signatures.</li>
 * <li>1024-2047 are reserved.</li>
 * <li>2048-4095 are used for parameters related to HIP transform types.</li>
 * <li>4096-61439 are reserved. However, a subset (32768 - 49141) of this can be
 * used for HIPL private parameters.</li>
 * <li>61440-62463 are used for signatures and signed MACs.</li>
 * <li>62464-63487 are used for parameters that fall outside of the signed area
 * of the packet.</li>
 * <li>63488-64511 are used for rendezvous and other relaying services.</li>
 * <li>64512-65535 are reserved.</li>
 * </ul>
 *
 * @defgroup hip_param_type_numbers HIP parameter type values
 * @see      hip_tlv
 * @see      hip_param_func
 * @see      <a href="http://hip4inter.net/documentation/drafts/draft-ietf-hip-base-06-pre180506.txt">
 *           draft-ietf-hip-base-06-pre180506</a> section 5.2.
 * @note     The order of the parameters is strictly enforced. The parameters
 *           @b must be in order from lowest to highest.
 * @{
 */

/** Defines the minimum parameter type value.
 * @note exclusive */
#define HIP_PARAM_MIN                  -1

#define HIP_PARAM_ESP_INFO             65
#define HIP_PARAM_R1_COUNTER           128
#define HIP_PARAM_LOCATOR              193
// NAT branch
/* 195 is temp value, check me later */
#define HIP_PARAM_STUN                 195
// end NAT branch
#define HIP_PARAM_HASH_CHAIN_VALUE     221 ///< lhip hash chain. 221 is is temporary.
#define HIP_PARAM_HASH_CHAIN_ANCHORS   222 ///< lhip hash chain anchors. 222 is temporary.
#define HIP_PARAM_HASH_CHAIN_PSIG      223 ///< lhip hash chain signature. 223 is temporary.
#define HIP_PARAM_PUZZLE               257
#define HIP_PARAM_SOLUTION             321
#define HIP_PARAM_CHALLENGE_RESPONSE   322
#define HIP_PARAM_SEQ                  385
#define HIP_PARAM_ACK                  449
#define HIP_PARAM_DIFFIE_HELLMAN       513
#define HIP_PARAM_HIP_TRANSFORM        577
//NAT branch
#define HIP_PARAM_NAT_TRANSFORM        608
#define HIP_PARAM_NAT_PACING           610
//end NAT branch

#define HIP_PARAM_ENCRYPTED            641
#define HIP_PARAM_HOST_ID              705
#define HIP_PARAM_CERT                 768
#define HIP_PARAM_NOTIFICATION         832
#define HIP_PARAM_ECHO_REQUEST_SIGN    897
#define HIP_PARAM_REG_INFO             930
#define HIP_PARAM_REG_REQUEST          932
#define HIP_PARAM_REG_RESPONSE         934
#define HIP_PARAM_REG_FAILED           936
#define HIP_PARAM_REG_FROM             950
#define HIP_PARAM_ECHO_RESPONSE_SIGN   961
#define HIP_PARAM_ECHO_RESPONSE_M      962
#define HIP_PARAM_ESP_TRANSFORM        4095
#define HIP_PARAM_ESP_PROT_TRANSFORMS  4120
#define HIP_PARAM_ESP_PROT_ANCHOR      4121
#define HIP_PARAM_ESP_PROT_BRANCH      4122
#define HIP_PARAM_ESP_PROT_SECRET      4123
#define HIP_PARAM_ESP_PROT_ROOT        4124
#define HIP_PARAM_LOCAL_NAT_PORT       4125
#define HIP_PARAM_PEER_NAT_PORT        4126

/* Range 32768 - 49141 for HIPL private network parameters. Please add
 * here only network messages, not internal messages!
 * @todo: move these to icomm.h */
#define HIP_PARAM_HIT                   32768
#define HIP_PARAM_IPV6_ADDR             32769
#define HIP_PARAM_DSA_SIGN_DATA         32770 /**< @todo change to digest */
#define HIP_PARAM_HI                    32771
#define HIP_PARAM_DH_SHARED_KEY         32772
#define HIP_PARAM_UNIT_TEST             32773
#define HIP_PARAM_EID_SOCKADDR          32774
#define HIP_PARAM_EID_ENDPOINT          32775 /**< Pass endpoint_hip structures into kernel */
#define HIP_PARAM_EID_IFACE             32776
#define HIP_PARAM_EID_ADDR              32777
#define HIP_PARAM_UINT                  32778 /**< Unsigned integer */
#define HIP_PARAM_KEYS                  32779
#define HIP_PARAM_PSEUDO_HIT            32780
/* unused, was HIP_PARAM_BLIND_NONCE 32785 */
/* unused, was HIP_PARAM_OPENDHT_GW_INFO 32786 */
#define HIP_PARAM_ENCAPS_MSG            32787
#define HIP_PARAM_PORTPAIR              32788
#define HIP_PARAM_SRC_ADDR              32789
#define HIP_PARAM_DST_ADDR              32790
/* free slot */
#define HIP_PARAM_HA_INFO               32792
/* free slot */
#define HIP_PARAM_CERT_SPKI_INFO        32794
#define HIP_PARAM_SRC_TCP_PORT          32795
#define HIP_PARAM_DST_TCP_PORT          32796
#define HIP_PARAM_IP_HEADER             32797
#define HIP_PARAM_PACKET_SIZE           32798
#define HIP_PARAM_TRAFFIC_TYPE          32799
#define HIP_PARAM_ADD_HIT               32800
#define HIP_PARAM_ADD_OPTION            32801
/* free slot */
#define HIP_PARAM_HCHAIN_ANCHOR         32803
#define HIP_PARAM_LSI                   32804
#define HIP_PARAM_HIT_LOCAL             32805
#define HIP_PARAM_HIT_PEER              32806
#define HIP_PARAM_IPV6_ADDR_LOCAL       32807
#define HIP_PARAM_IPV6_ADDR_PEER        32808
#define HIP_PARAM_HEARTBEAT             32809
#define HIP_PARAM_CERT_X509_REQ         32810
#define HIP_PARAM_CERT_X509_RESP        32811
#define HIP_PARAM_ESP_PROT_TFM          32812
#define HIP_PARAM_TRANSFORM_ORDER       32813
/* free slots */
#define HIP_PARAM_SECRET                32817
#define HIP_PARAM_BRANCH_NODES          32818
#define HIP_PARAM_ROOT                  32819
#define HIP_PARAM_HIT_TO_IP_SET         32820
/* #define HIP_PARAM_TURN_INFO             32821 */
#define HIP_PARAM_ITEM_LENGTH           32822
/* End of HIPL private parameters. */

#define HIP_PARAM_HMAC                  61505
#define HIP_PARAM_HMAC2                 61569
#define HIP_PARAM_HIP_SIGNATURE2        61633
#define HIP_PARAM_HIP_SIGNATURE         61697
#define HIP_PARAM_ECHO_RESPONSE         63425
#define HIP_PARAM_ECHO_REQUEST          63661
#define HIP_PARAM_RELAY_FROM            63998 ///< HIP relay related parameter @note former FROM_NAT
#define HIP_PARAM_RELAY_TO              64002 ///< HIP relay related parameter @note Former VIA_RVS_NAT
//#define HIP_PARAM_REG_FROM            64010
#define HIP_PARAM_TO_PEER               64006
#define HIP_PARAM_FROM_PEER             64008
#define HIP_PARAM_ECHO_REQUEST_M        65332
#define HIP_PARAM_CHALLENGE_REQUEST     65334
#define HIP_PARAM_FROM                  65498
#define HIP_PARAM_RVS_HMAC              65500
#define HIP_PARAM_VIA_RVS               65502
#define HIP_PARAM_RELAY_HMAC            65520 ///< HIP relay related parameter
#define HIP_PARAM_HOSTNAME              65521
#define HIP_PARAM_HIT_INFO              65524

#define HIP_PARAM_MAX                   65536 ///< Defines the maximum parameter type value. @note exclusive
/* @} */

/**
 * HIP NOTIFICATION parameter values.
 *
 * NOTIFICATION parameter error types used in the "Notify Message Type"-field of
 * NOTIFICATION parameter as specified in section 5.2.16. of
 * draft-ietf-hip-base-06.
 *
 * @defgroup notification NOTIFICATION parameter values
 * @see      hip_notification
 * @{
 */
/** Sent if the parameter type has the "critical" bit set and the
 *  parameter type is not recognized.  Notification Data contains the
 *  two octet parameter type. */
#define HIP_NTF_UNSUPPORTED_CRITICAL_PARAMETER_TYPE  1
/** Indicates that the HIP message received was invalid because some
 *  type, length, or value was out of range or because the request was
 *  rejected for policy reasons.  To avoid a denial of service attack
 *  using forged messages, this status may only be returned for
 *  packets whose HMAC (if present) and SIGNATURE have been verified.
 *  This status MUST be sent in response to any error not covered by
 *  one of the other status types, and should not contain details to
 *  avoid leaking information to someone probing a node.  To aid
 *  debugging, more detailed error information SHOULD be written to a
 *  console or log. */
#define HIP_NTF_INVALID_SYNTAX                       7
/** None of the proposed group IDs was acceptable. */
#define HIP_NTF_NO_DH_PROPOSAL_CHOSEN               14
/** The D-H Group ID field does not correspond to one offered
 *  by the Responder. */
#define HIP_NTF_INVALID_DH_CHOSEN                   15
/** None of the proposed HIP Transform crypto suites was acceptable. */
#define HIP_NTF_NO_HIP_PROPOSAL_CHOSEN              16
/** The HIP Transform crypto suite does not correspond to one offered
 *  by the Responder. */
#define HIP_NTF_INVALID_HIP_TRANSFORM_CHOSEN        17
/** Sent in response to a HIP signature failure, except when the
 *  signature verification fails in a NOTIFY message. */
#define HIP_NTF_AUTHENTICATION_FAILED               24
/** Sent in response to a HIP checksum failure. */
#define HIP_NTF_CHECKSUM_FAILED                     26
/** Sent in response to a HIP HMAC failure. */
#define HIP_NTF_HMAC_FAILED                         28
/** The Responder could not successfully decrypt the ENCRYPTED
 *  parameter. */
#define HIP_NTF_ENCRYPTION_FAILED                   32
/** Sent in response to a failure to validate the peer's HIT from the
 *  corresponding HI. */
#define HIP_NTF_INVALID_HIT                         40
/** The Responder is unwilling to set up an association for some
 *  policy reason (e.g.\ received HIT is NULL and policy does not
 *  allow opportunistic mode). */
#define HIP_NTF_BLOCKED_BY_POLICY                   42
/** The Responder is unwilling to set up an association as it is
 *  suffering under some kind of overload and has chosen to shed load
 *  by rejecting your request.  You may retry if you wish, however you
 *  MUST find another (different) puzzle solution for any such
 *  retries.  Note that you may need to obtain a new puzzle with a new
 *  I1/R1 exchange. */
#define HIP_NTF_SERVER_BUSY_PLEASE_RETRY            44
/** The Responder has received your I2 but had to queue the I2 for
 *  processing.  The puzzle was correctly solved and the Responder is
 *  willing to set up an association but has currently a number of I2s
 *  in processing queue.  R2 will be sent after the I2 has been
 *  processed. */
#define HIP_NTF_I2_ACKNOWLEDGEMENT                  46
/* @} */

#define HIP_HIP_RESERVED                0
#define HIP_HIP_AES_SHA1                1
#define HIP_HIP_3DES_SHA1               2
#define HIP_HIP_3DES_MD5                3
#define HIP_HIP_BLOWFISH_SHA1           4
#define HIP_HIP_NULL_SHA1               5
#define HIP_HIP_NULL_MD5                6

#define HIP_TRANSFORM_HIP_MAX           6
#define HIP_TRANSFORM_ESP_MAX           6
#define HIP_LOWER_TRANSFORM_TYPE 2048
#define HIP_UPPER_TRANSFORM_TYPE 4095

#define HIP_ESP_RESERVED                0
#define HIP_ESP_AES_SHA1                1
#define HIP_ESP_3DES_SHA1               2
#define HIP_ESP_3DES_MD5                3
#define HIP_ESP_BLOWFISH_SHA1           4
#define HIP_ESP_NULL_SHA1               5
#define HIP_ESP_NULL_MD5                6

/* Only for testing!!! */
#define HIP_ESP_NULL_NULL            0x0

#define HIP_HI_DSA                    3
#define HIP_SIG_DSA                   3
#define HIP_HI_RSA                    5
#define HIP_SIG_RSA                   5
#define HIP_HI_ECDSA                  7  // according to RFC5201-bis
#define HIP_SIG_ECDSA                 7

#define HIP_ANY_ALGO                  -1

/* Elliptic curves */
enum hip_cuve_id {
    UNSUPPORTED_CURVE,
    NIST_ECDSA_256,
    NIST_ECDSA_384,
    brainpoolP160r1,
    NIST_ECDSA_160   // substitute for brainpoolP160r1
};

#define HIP_DIGEST_MD5                1
#define HIP_DIGEST_SHA1               2
#define HIP_DIGEST_SHA1_HMAC          3
#define HIP_DIGEST_MD5_HMAC           4

#define HIP_DIRECTION_ENCRYPT         1
#define HIP_DIRECTION_DECRYPT         2

#define HIP_KEYMAT_INDEX_NBR_SIZE     1

#define HIP_VERIFY_PUZZLE             0
#define HIP_SOLVE_PUZZLE              1
#define HIP_PUZZLE_OPAQUE_LEN         2

#define HIP_DSA_SIGNATURE_LEN        41

#define HIP_AH_SHA_LEN               20

#define HIP_NAT_PROTO_UDP            17

#define HIP_HOST_ID_HOSTNAME_LEN_MAX 64

#define HIP_MAX_KEY_LEN 32 /* max. draw: 256 bits! */

#define HIP_VER_RES                 0x01     /* Version 1, reserved 0 */
#define HIP_USER_VER_RES            0x10       /* Internal messages */

/**
 * @defgroup hip_ha_controls HIP host association controls
 *
 * These are bitmasks used in the @c hip_hadb_state stucture fields
 * @c local_controls and @c peer_controls.
 *
 * @c local_controls defines the flags of the current host, while peer_controls
 * define the flags of the peer. The flags are used to indicate the state or
 * status of the host. A status can be, for example, that we have requested
 * for a service or that we are capable of offering a service.
 *
 * Bitmask for local controls:
 * <pre>
 * 0000 0000 0000 0000
 * |||| |||| |||| |||+- 0x0001 We have requested an unsupported service.
 * |||| |||| |||| ||+-- 0x0002 - free -
 * |||| |||| |||| |+--- 0x0004 - free -
 * |||| |||| |||| +---- 0x0008 - free -
 * |||| |||| |||+------ 0x0010 - free -
 * |||| |||| ||+------- 0x0020 - free -
 * |||| |||| |+-------- 0x0040 - free -
 * |||| |||| +--------- 0x0080 - free -
 * |||| |||+----------- 0x0100 - free -
 * |||| ||+------------ 0x0200 - free -
 * |||| |+------------- 0x0400 - free -
 * |||| +-------------- 0x0800 We have granted the peer full relay service
 * |||+---------------- 0x1000 We have requested full relay service.
 * ||+----------------- 0x2000 Unused
 * |+------------------ 0x4000 We have requested HIP relay service.
 * +------------------- 0x8000 We have requested RVS service.
 * </pre>
 * Bitmask for peer controls:
 * <pre>
 * 0000 0000 0000 0000
 * |||| |||| |||| |||+- 0x0001 Peer granted an unsupported service to us.
 * |||| |||| |||| ||+-- 0x0002 Peer offers an unsupported service.
 * |||| |||| |||| |+--- 0x0004 Peer refused to grant us an unsupported service.
 * |||| |||| |||| +---- 0x0008 - free -
 * |||| |||| |||+------ 0x0010 - free -
 * |||| |||| ||+------- 0x0020 Peer has refused to grant us full relay service
 * |||| |||| |+-------- 0x0040 Peer refused to grant us HIP relay service.
 * |||| |||| +--------- 0x0080 Peer refused to grant us RVS service.
 * |||| |||+----------- 0x0100 - free -
 * |||| ||+------------ 0x0200 - free -
 * |||| |+------------- 0x0400 Peer has granted us full relay service
 * |||| +-------------- 0x0800 Peer granted HIP relay service to us.
 * |||+---------------- 0x1000 Peer granted RVS service to us.
 * ||+----------------- 0x2000 Peer offers full relay service
 * |+------------------ 0x4000 Peer offers HIP relay service.
 * +------------------- 0x8000 Peer offers RVS service.
 * </pre>
 *
 * @note There has been some confusion about which bit does what and which of
 * the control fields to alter. To avoid this confusion, please do not alter
 * the @c local_controls and @c peer_controls fields directly. Instead use
 * functions hip_hadb_set_local_controls(), hip_hadb_set_peer_controls(),
 * hip_hadb_cancel_local_controls(), hip_hadb_cancel_peer_controls().
 * @note Do not confuse these values with HIP packet Controls values.
 * @{
 */
/* REMEMBER TO UPDATE BITMAP IN DOC/DOXYGEN.H WHEN YOU ADD/CHANGE THESE! */
#define HIP_HA_CTRL_NONE                    0x0000 ///< Clears all control values. To clear all local controls call hip_hadb_set_local_controls() with this mask. To clear all peer controls call hip_hadb_set_peer_controls() with this mask.
#define HIP_HA_CTRL_LOCAL_REQ_UNSUP         0x0001 ///< The host association has requested unsupported service in an I1 or an UPDATE packet. This flag is set if the user requests a service that is unsupported in HIPL. A service request of such kind is possible using <code>hipconf add server</code> with service numbers.
#define HIP_HA_CTRL_LOCAL_REQ_RELAY         0x4000 ///< The host association has requested HIP relay service in an I1 or an UPDATE packet.
#define HIP_HA_CTRL_LOCAL_REQ_RVS           0x8000 ///< The host association has requested rendezvous service in an I1 or an UPDATE packet.
#define HIP_HA_CTRL_LOCAL_REQ_FULLRELAY     0x1000
/** An OR mask of every existing local request mask. */
/* Keep inside parentheses. */
#define HIP_HA_CTRL_LOCAL_REQ_ANY        ( \
        HIP_HA_CTRL_LOCAL_REQ_UNSUP | \
        HIP_HA_CTRL_LOCAL_REQ_RELAY | \
        HIP_HA_CTRL_LOCAL_REQ_RVS   | \
        HIP_HA_CTRL_LOCAL_REQ_FULLRELAY \
        )

#define HIP_HA_CTRL_LOCAL_GRANTED_FULLRELAY 0x0800

/** The peer has granted us unsupported service in a REG_RESPONSE parameter
 *  received in an R2 packet or an UPDATE packet. The peer has granted us a
 *  service that HIPL does not support. */
#define HIP_HA_CTRL_PEER_GRANTED_UNSUP      0x0001
/** The peer has granted us relay service in a REG_RESPONSE parameter
 *  received in an R2 packet or an UPDATE packet. */
#define HIP_HA_CTRL_PEER_GRANTED_RELAY      0x0800
/** The peer has granted us rendezvous service in a REG_RESPONSE parameter
 *  received in an R2 packet or an UPDATE packet. */
#define HIP_HA_CTRL_PEER_GRANTED_RVS        0x1000
/** The peer has announced in an R1 or UPDATE packet that it offers an
 *  unsupported service. */
#define HIP_HA_CTRL_PEER_GRANTED_FULLRELAY   0x400

#define HIP_HA_CTRL_PEER_UNSUP_CAPABLE      0x0002
/** The peer has announced in an R1 or UPDATE packet that it offers HIP
 *  relay service. */
#define HIP_HA_CTRL_PEER_RELAY_CAPABLE      0x4000
/** The peer has announced in an R1 or UPDATE packet that it offers
 *  rendezvous service. */
#define HIP_HA_CTRL_PEER_RVS_CAPABLE        0x8000
#define HIP_HA_CTRL_PEER_FULLRELAY_CAPABLE  0x2000

#define HIP_HA_CTRL_PEER_REFUSED_UNSUP      0x0004
#define HIP_HA_CTRL_PEER_REFUSED_RELAY      0x0040
#define HIP_HA_CTRL_PEER_REFUSED_RVS        0x0080
#define HIP_HA_CTRL_PEER_REFUSED_FULLRELAY  0x0020

/* @} */

/**
 * @defgroup hip_packet_controls HIP packet Controls field values
 *
 * These are the values that are used in the HIP message Controls field. More
 * importantantly, these are <span style="color:#f00;">the only values allowed
 * in that field.</span> Do not put any other bits on wire in the Controls
 * field.
 * @note Do not confuse these values with HIP host association Control values.
 * @{
 */
#define HIP_PACKET_CTRL_NON              0x0000 /**< HIP packet with empty Controls field */
#define HIP_PACKET_CTRL_ANON             0x0001 /**< HIP packet Controls value */
/* unused, was HIP_PACKET_CTRL_BLIND 0x0004 */
/* @} */

/**
 * @defgroup hip_services Additional HIP services
 *
 * Registration types for registering to a service as specified in
 * draft-ietf-hip-registration-02. These are the registration types used in
 * @c REG_INFO, @c REG_REQUEST, @c REG_RESPONSE and @c REG_FAILED parameters.
 * Numbers 0-200 are reserved by IANA.
 * Numbers 201 - 255 are reserved by IANA for private use.
 * @{
 */
#define HIP_SERVICE_RENDEZVOUS             1 ///< Rendezvous service for relaying I1 packets
#define HIP_SERVICE_RELAY                  2 ///< UDP encapsulated relay service for HIP packets
#define HIP_SERVICE_FULLRELAY            204
/** Total number of services, which must equal the sum of all existing services. */
/* IMPORTANT! This must be the sum of above services. */
#define HIP_TOTAL_EXISTING_SERVICES        3
/* @} */

/* Registration failure types as specified in draft-ietf-hip-registration-02.
 * Numbers 0-200 are reserved by IANA.
 * Numbers 201 - 255 are reserved by IANA for private use. */
#define HIP_REG_INSUFFICIENT_CREDENTIALS 0
#define HIP_REG_TYPE_UNAVAILABLE         1
/** HIPL specific failure type to indicate that the requested service cannot
 *  co-exist with a service that has been already granted to the client. The
 *  client is required to cancel the overlapping service before registering. */
#define HIP_REG_CANCEL_REQUIRED          201
/** HIPL specific failure type to indicate that the requested service is not
 *  available due to transient conditions. */
#define HIP_REG_TRANSIENT_CONDITIONS     202
/** Number of existing failure types. */
#define HIP_TOTAL_EXISTING_FAILURE_TYPES 4
/* A shorthand to init an array having all possible registration failure
 * types. */
#define HIP_ARRAY_INIT_REG_FAILURES \
    {HIP_REG_INSUFFICIENT_CREDENTIALS, HIP_REG_TYPE_UNAVAILABLE, \
     HIP_REG_CANCEL_REQUIRED, HIP_REG_TRANSIENT_CONDITIONS}


/* Returns length of TLV option (contents) with padding. */
#define HIP_LEN_PAD(len) \
    ((((len) & 0x07) == 0) ? (len) : ((((len) >> 3) << 3) + 8))

#define HIP_UDP_ZERO_BYTES_LEN 4 /* in bytes */

#define HIP_MAX_RSA_KEY_LEN 4096

typedef uint8_t hip_hdr_type_t;
typedef uint8_t hip_hdr_len_t;
typedef uint16_t se_family_t;
typedef uint16_t se_length_t;
typedef uint16_t se_hip_flags_t;
typedef uint16_t hip_hdr_err_t;
typedef uint16_t hip_tlv_type_t;
typedef uint16_t hip_tlv_len_t;
typedef uint16_t hip_transform_suite_t;
typedef uint16_t hip_controls_t;
typedef uint32_t sa_eid_t;
typedef struct in6_addr hip_hit_t;
typedef struct in_addr hip_lsi_t;

struct hip_crypto_key {
    uint8_t key[HIP_MAX_KEY_LEN];
};

/* RFC2535 3.1 KEY RDATA format */
struct hip_host_id_key_rdata {
    uint16_t flags;
    uint8_t  protocol;
    uint8_t  algorithm;
    /* fixed part ends */
} __attribute__ ((packed));


struct hip_host_id {
    hip_tlv_type_t               type;
    hip_tlv_len_t                length;
    uint16_t                     hi_length;
    uint16_t                     di_type_length;
    struct hip_host_id_key_rdata rdata;
    /* Space to accommodate the largest supported key */
    unsigned char                key[HIP_MAX_RSA_KEY_LEN / 8 + 4];
    char                         hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
} __attribute__ ((packed));

struct hip_host_id_priv {
    hip_tlv_type_t               type;
    hip_tlv_len_t                length;
    uint16_t                     hi_length;
    uint16_t                     di_type_length;
    struct hip_host_id_key_rdata rdata;
    /* Space for the full private key */
    unsigned char                key[HIP_MAX_RSA_KEY_LEN / 16 * 9 + 4];
    char                         hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
} __attribute__ ((packed));


/**
 * Localhost Host Identity. Used only internally in the implementation.
 * Used for wrapping anonymous bit with the corresponding HIT.
 */
struct hip_lhi {
    struct in6_addr hit;
    uint16_t        anonymous;        /**< Is this an anonymous HI */
    uint16_t        algo;        /**< HIP_HI_RSA or HIP_HI_DSA or HIP_ECDSA*/
} __attribute__ ((packed));


struct hip_keymat_keymat {
    size_t offset;        /**< Offset into the key material */
    size_t keymatlen;     /**< Length of the key material */
    void * keymatdst;     /**< Pointer to beginning of key material */
};

struct esp_prot_preferred_tfms {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint8_t        num_transforms;
    // this will also contain the UNUSED transform
    uint8_t        transforms[MAX_NUM_TRANSFORMS];
} __attribute__ ((packed));

struct esp_prot_anchor {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint8_t        transform;
    uint32_t       hash_item_length;
    // contains active and next anchor
    unsigned char  anchors[2 * MAX_HASH_LENGTH];
} __attribute__ ((packed));

struct esp_prot_branch {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint32_t       anchor_offset;
    uint32_t       branch_length;
    unsigned char  branch_nodes[MAX_HTREE_DEPTH * MAX_HASH_LENGTH];
} __attribute__ ((packed));

struct esp_prot_secret {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint8_t        secret_length;
    unsigned char  secret[MAX_HASH_LENGTH];
} __attribute__ ((packed));

struct esp_prot_root {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint8_t        root_length;
    unsigned char  root[MAX_HASH_LENGTH];
} __attribute__ ((packed));

/**
 * Used in executing a unit test case in a test suite in the kernel module.
 */
struct hip_unit_test {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint16_t       suiteid;
    uint16_t       caseid;
} __attribute__ ((packed));

/** Structure describing an endpoint. This structure is used by the resolver in
 * the userspace, so it is not length-padded like HIP parameters. All of the
 * members are in network byte order.
 */
struct endpoint {
    se_family_t family;          /**< PF_HIP, PF_XX */
    se_length_t length;          /**< length of the whole endpoint in octets */
};

/**
 * @note not padded
 */
struct endpoint_hip {
    se_family_t    family;          /**< PF_HIP */
    se_length_t    length;          /**< length of the whole endpoint in octets */
    se_hip_flags_t flags;           /**< e.g. ANON or HIT */
    uint8_t        algo;
    hip_lsi_t      lsi;
    union {
        struct hip_host_id_priv host_id;
        struct in6_addr         hit;
    } id;
};

/**
 * Use accessor functions defined in builder.c, do not access members
 * directly to avoid hassle with byte ordering and number conversion.
 */
struct hip_common {
    uint8_t         payload_proto;
    uint8_t         payload_len;
    uint8_t         type_hdr;
    uint8_t         ver_res;
    uint16_t        checksum;
    uint16_t        control;
    struct in6_addr hits;       /**< Sender HIT   */
    struct in6_addr hitr;       /**< Receiver HIT */
} __attribute__ ((packed));

struct hip_common_user {
    uint16_t        len;
    uint8_t         type;
    uint8_t         version;
    uint16_t        error;
    uint16_t        control;
    struct in6_addr hitr;       /* unused  */
    struct in6_addr hits;       /* unused */
} __attribute__ ((packed));

/**
 * Use accessor functions defined in hip_build.h, do not access members
 * directly to avoid hassle with byte ordering and length conversion.
 */
struct hip_tlv_common {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
} __attribute__ ((packed));

struct hip_esp_info {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint16_t       reserved;
    uint16_t       keymat_index;
    uint32_t       old_spi;
    uint32_t       new_spi;
} __attribute__ ((packed));

/**
 * Type-length-value data structures in Host Identity Protocol (HIP).
 *
 * @defgroup hip_tlv HIP TLV data structures
 * @see      hip_param_type_numbers
 * @see      hip_param_func
 * @see      <a href="http://hip4inter.net/documentation/drafts/draft-ietf-hip-base-06-pre180506.txt">
 *           draft-ietf-hip-base-06-pre180506</a> section 5.2.
 * @note     The order of the parameters is strictly enforced. The parameters
 *           @b must be in order from lowest to highest.
 * @{
 */
struct hip_r1_counter {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint32_t       reserved;
    uint64_t       generation;
} __attribute__ ((packed));

struct hip_puzzle {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint8_t        K;
    uint8_t        lifetime;
    uint8_t        opaque[HIP_PUZZLE_OPAQUE_LEN];
    uint64_t       I;
} __attribute__ ((packed));

struct hip_solution {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint8_t        K;
    uint8_t        reserved;
    uint8_t        opaque[HIP_PUZZLE_OPAQUE_LEN];
    uint64_t       I;
    uint64_t       J;
} __attribute__ ((packed));



struct hip_challenge_request {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint8_t        K;
    uint8_t        lifetime;
    uint8_t        opaque[24];        /**< variable length */
} __attribute__ ((packed));

struct hip_challenge_response {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint8_t        K;
    uint8_t        lifetime;
    uint64_t       J;
    uint8_t        opaque[24];        /**< variable length */
} __attribute__ ((packed));

struct hip_dh_public_value {
    uint8_t  group_id;
    uint16_t pub_len;
    /* fixed part ends */
    uint8_t  public_value[0];
} __attribute__ ((packed));

struct hip_diffie_hellman {
    hip_tlv_type_t             type;
    hip_tlv_len_t              length;
    struct hip_dh_public_value pub_val;
} __attribute__ ((packed));

struct hip_hip_transform {
    hip_tlv_type_t        type;
    hip_tlv_len_t         length;
    hip_transform_suite_t suite_id[HIP_TRANSFORM_HIP_MAX];
} __attribute__ ((packed));

struct hip_esp_transform {
    hip_tlv_type_t        type;
    hip_tlv_len_t         length;
    uint16_t              reserved;
    hip_transform_suite_t suite_id[HIP_TRANSFORM_ESP_MAX];
} __attribute__ ((packed));


struct hip_encrypted_aes_sha1 {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint32_t       reserved;
    uint8_t        iv[16];
    /* fixed part ends */
} __attribute__ ((packed));

struct hip_encrypted_3des_sha1 {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint32_t       reserved;
    uint8_t        iv[8];
    /* fixed part ends */
} __attribute__ ((packed));

struct hip_encrypted_null_sha1 {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint32_t       reserved;
    /* fixed part ends */
} __attribute__ ((packed));

struct hip_sig {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint8_t        algorithm;
    uint8_t        signature[0];   /**< variable length */
    /* fixed part end */
} __attribute__ ((packed));

struct hip_sig2 {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint8_t        algorithm;
    uint8_t        signature[0];   /**< variable length */
    /* fixed part end */
} __attribute__ ((packed));

struct hip_seq {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint32_t       update_id;
} __attribute__ ((packed));

struct hip_ack {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint32_t       peer_update_id; /**< n items */ /* This only fits one... */
} __attribute__ ((packed));

struct hip_notification {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint16_t       reserved;
    uint16_t       msgtype;
    uint8_t        data[0]; /**< A pointer to the notification data */
} __attribute__ ((packed));

struct hip_hmac {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint8_t        hmac_data[HIP_AH_SHA_LEN];
} __attribute__ ((packed));

struct hip_cert {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint8_t        cert_group;
    uint8_t        cert_count;
    uint8_t        cert_id;
    uint8_t        cert_type;
    /* end of fixed part */
} __attribute__ ((packed));

struct hip_echo_request {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    /* opaque */
} __attribute__ ((packed));

struct hip_echo_response {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    /* opaque */
} __attribute__ ((packed));

/** draft-ietf-hip-rvs-05 */
/** Parameter containing the original source IP address of a HIP packet. */
struct hip_from {
    hip_tlv_type_t type;   /**< Type code for the parameter. */
    hip_tlv_len_t  length;  /**< Length of the parameter contents in bytes. */
    uint8_t        address[16]; /**< IPv6 address */
} __attribute__ ((packed));

/** draft-ietf-hip-rvs-05 */
/** Parameter containing the IP addresses of traversed rendezvous servers. */
struct hip_via_rvs {
    hip_tlv_type_t type;   /**< Type code for the parameter. */
    hip_tlv_len_t  length;  /**< Length of the parameter contents in bytes. */
    uint8_t        address[0]; /**< Rendezvous server addresses */
} __attribute__ ((packed));

/** draft-ietf-hip-nat-traversal-02 */
/** Parameter containing the original source IP address and port number
 * of a HIP packet. */
struct hip_relay_from {
    hip_tlv_type_t type;  /**< Type code for the parameter. */
    hip_tlv_len_t  length;  /**< Length of the parameter contents in bytes. */
    in_port_t      port; /**< Port number. */
    uint8_t        protocol; /**< Protocol */
    int8_t         reserved; /**< Reserved */
    uint8_t        address[16]; /**< IPv6 address */
} __attribute__ ((packed));

/** draft-ietf-hip-nat-traversal-02 */
/** Parameter containing the IP addresses and source ports of traversed
 *  rendezvous servers. */
struct hip_relay_to {
    hip_tlv_type_t  type; /**< Type code for the parameter. */
    hip_tlv_len_t   length; /**< Length of the parameter contents in bytes. */
    in_port_t       port; /**< Port number. */
    uint8_t         protocol; /**< Protocol */
    uint8_t         reserved; /**< Reserved */
    struct in6_addr address;  /**< IPv6 address */
} __attribute__ ((packed));

/** This structure is used by the native API to carry local and peer
 *  identities from libc (setmyeid and setpeereid calls) to the HIP
 *  socket handler (setsockopt). It is almost the same as endpoint_hip,
 *  but it is length-padded like HIP parameters to make it usable with
 *  the builder interface. */
struct hip_eid_endpoint {
    hip_tlv_type_t      type;
    hip_tlv_len_t       length;
    struct endpoint_hip endpoint;
} __attribute__ ((packed));

struct hip_reg_info {
    hip_tlv_type_t type;     /**< Type code for the parameter. */
    hip_tlv_len_t  length;     /**< Length of the parameter contents in bytes. */
    uint8_t        min_lifetime;
    uint8_t        max_lifetime;
    uint8_t        reg_type[0];
} __attribute__ ((packed));

struct hip_reg_request {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint8_t        lifetime;
    uint8_t        reg_type[0];
} __attribute__ ((packed));

struct hip_reg_response {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint8_t        lifetime;
    uint8_t        reg_type[0];
} __attribute__ ((packed));

struct hip_reg_failed {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    uint8_t        failure_type;
    uint8_t        reg_type[0];
} __attribute__ ((packed));

struct hip_keys {
    hip_tlv_type_t        type;
    hip_tlv_len_t         length;
    uint16_t              operation;
    uint16_t              alg_id;
    uint8_t               address[16];
    uint8_t               hit[16];
    uint8_t               peer_hit[16];
    uint32_t              spi;
    uint32_t              spi_old;
    uint16_t              key_len;
    struct hip_crypto_key enc;
} __attribute__ ((packed));

struct hip_cert_x509_req {
    hip_tlv_type_t  type;
    hip_tlv_len_t   length;
    struct in6_addr addr;
} __attribute__ ((packed));

struct hip_cert_x509_resp {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    unsigned char  der[1024];
    int            der_len;
} __attribute__ ((packed));

struct hip_transformation_order {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    int            transorder;
} __attribute__ ((packed));


#define HIT_TO_IP_ZONE_MAX_LEN 256

struct hip_hit_to_ip_set {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    char           name[HIT_TO_IP_ZONE_MAX_LEN];
} __attribute__ ((packed));

struct hip_heartbeat {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    int            heartbeat;
} __attribute__ ((packed));

/** draft-ietf-hip-nat-traversal-02 */
struct hip_reg_from {
    hip_tlv_type_t  type;    /**< Type code for the parameter. */
    hip_tlv_len_t   length;    /**< Length of the parameter contents in bytes. */
    in_port_t       port; /**< Port number. */
    uint8_t         protocol; /**< Protocol */
    uint8_t         reserved; /**< Reserved */
    struct in6_addr address;     /**< IPv6 address */
} __attribute__ ((packed));

struct hip_port_info {
    hip_tlv_type_t type;      /**< Type code for the parameter. */
    hip_tlv_len_t  length;      /**< Length of the parameter contents in bytes. */
    in_port_t      port;      /**< Port number. */
} __attribute__ ((packed));

/* @} */

struct sockaddr_hip {
    sa_family_t ship_family;
    in_port_t   ship_port;
    uint32_t    ship_pad;
    uint64_t    ship_flags;
    hip_hit_t   ship_hit;
    uint8_t     ship_reserved[16];
} __attribute__ ((packed));

/**
 * A data structure for storing the source and destination ports of a packet.
 */
struct hip_portpair {
    in_port_t src_port;     /**< The source port of an incoming packet. */
    in_port_t dst_port;     /**< The destination port of an incoming packet. */
};

/**
 * Structure used to pass information around during packet handling.
 */
struct hip_packet_context {
    struct hip_common         *input_msg;  /**< Incoming message. */
    struct hip_common         *output_msg; /**< Outgoing message. */
    struct in6_addr            src_addr;   /**< Packet origin. */
    struct in6_addr            dst_addr;   /**< Packet destination. */
    struct hip_portpair        msg_ports;  /**< Used ports. */
    struct hip_hadb_state     *hadb_entry; /**< Host association database entry. */
    uint8_t                    error;      /**< Abort further processing if not 0 */
};


#endif /* HIP_LIB_CORE_PROTODEFS_H */
