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

#ifndef HIP_LIB_CORE_PERFORMANCE_H
#define HIP_LIB_CORE_PERFORMANCE_H

/**
 * @file
 * Primitive performance measurement
 */

#include <stdio.h>

/** This performace set holds all measurements */
struct perf_set {
    /** @brief A pointer to names of output files */
    FILE **files;
    /** @brief A list of names of the perf sets. */
    char **names;
    /** @brief A list timeval time structs. */
    struct timeval *times;
    /** @brief A list of measured results. */
    double *result;
    /** @brief The number of perf sets. */
    int num_files;
    /** @brief A linecount */
    int *linecount;
    /** @brief Are the necessary files opened? 1=TRUE, 0=FALSE. */
    int files_open;
    /** @brief Are measurements running? This is an integer field of the length num_files. */
    int *running;
    /** @brief Are the measurements writable (completed)? This is an integer field of the length num_files. */
    int *writable;
};

struct perf_set *hip_perf_create(int num);
int hip_perf_set_name(struct perf_set *perf_set, int slot, const char *name);
int hip_perf_open(struct perf_set *perf_set);
void hip_perf_start_benchmark(struct perf_set *perf_set, int slot);
void hip_perf_stop_benchmark(struct perf_set *perf_set, int slot);
int hip_perf_write_benchmark(struct perf_set *perf_set, int slot);
void hip_perf_destroy(struct perf_set *perf_set);

enum perf_sensor {
    PERF_I1,
    PERF_I1_R1,             // time at initiator between sending I1 and receiving R1
    PERF_R1,
    PERF_R1_I2,             // time at responder between sending R1 and receiving I2
    PERF_I2,
    PERF_I2_R2,             // time at initiator between sending I2 and receiving R2
    PERF_R2,
    PERF_R2_I3,             // time at responder between sending R2 and receiving I3
    PERF_I3,
    PERF_CONN_U1,
    PERF_CONN_U2,
    PERF_CONN_U3,
    PERF_MBOX_I1,
    PERF_MBOX_R1,
    PERF_MBOX_I2,
    PERF_MBOX_R2,
    PERF_MBOX_I3,
    PERF_MBOX_PACKET,


    PERF_MBOX_R1_VERIFY_HOST_SIG,
    PERF_MBOX_R1_VERIFY_WITH_POLICY,
    PERF_MBOX_R1_GEN_DH_SHARED_SECRET,
    PERF_MBOX_R1_ADD_INFO_REQ_U,
    PERF_MBOX_R1_ADD_INFO_REQ_S,
    PERF_MBOX_R1_ADD_INFO_REQ_SELECTIVE_S,
    PERF_MBOX_R1_SERVICE_SIGNATURE,
    PERF_MBOX_R1_HASH_SERVICE_OFFER,

    PERF_MBOX_I2_VERIFY_HOST_SIG,
    PERF_MBOX_I2_VERIFY_HOST_SELECTIVE_SIG,
    PERF_MBOX_I2_VERIFY_USER_SIG,
    PERF_MBOX_I2_VERIFY_USER_SELECTIVE_SIG,
    PERF_MBOX_I2_VERIFY_ACK_U,
    PERF_MBOX_I2_VERIFY_ACK_S,
    PERF_MBOX_I2_VERIFY_ACK_SELECTIVE_S,
    PERF_MBOX_I2_BUILD_PARAM_REM_LIST,
    PERF_MBOX_I2_GEN_DH_SHARED_SECRET,
    PERF_MBOX_I2_DEC_SYMM_KEY_DH,
    PERF_MBOX_I2_DEC_SYMM_KEY_RSA,
    PERF_MBOX_I2_DEC_ENDPOINT_SECRET,
    PERF_MBOX_I2_VERIFY_INFO_REQ,
    PERF_MBOX_I2_VERIFY_WITH_POLICY,
    PERF_MBOX_I2_ADD_INFO_REQ_U,
    PERF_MBOX_I2_ADD_INFO_REQ_S,
    PERF_MBOX_I2_ADD_INFO_REQ_SELECTIVE_S,
    PERF_MBOX_I2_SERVICE_SIGNATURE,
    PERF_MBOX_I2_HASH_SERVICE_OFFER,
    PERF_MBOX_I2_REM_PARAMS,

    PERF_MBOX_R2_VERIFY_HOST_SIG,
    PERF_MBOX_R2_VERIFY_HOST_SELECTIVE_SIG,
    PERF_MBOX_R2_VERIFY_USER_SIG,
    PERF_MBOX_R2_VERIFY_USER_SELECTIVE_SIG,
    PERF_MBOX_R2_VERIFY_ACK_U,
    PERF_MBOX_R2_VERIFY_ACK_S,
    PERF_MBOX_R2_VERIFY_ACK_SELECTIVE_S,
    PERF_MBOX_R2_BUILD_PARAM_REM_LIST,
    PERF_MBOX_R2_DEC_SYMM_KEY_DH,
    PERF_MBOX_R2_DEC_SYMM_KEY_RSA,
    PERF_MBOX_R2_DEC_ENDPOINT_SECRET,
    PERF_MBOX_R2_VERIFY_INFO_REQ,
    PERF_MBOX_R2_VERIFY_WITH_POLICY,
    PERF_MBOX_R2_REM_PARAMS,

    PERF_MBOX_I2_VERIFY_USER_PUBKEY,
    PERF_MBOX_R2_VERIFY_USER_PUBKEY,
    PERF_MBOX_I3_VERIFY_HOST_SIG,
    PERF_MBOX_I3_VERIFY_USER_SIG,
    PERF_MBOX_NOTIFY,
    PERF_MBOX_UPDATE,
    PERF_MBOX_NOTIFY_VERIFY_HOST_SIG,
    PERF_MBOX_UPDATE_VERIFY_HOST_SIG,

    PERF_MBOX_U1,
    PERF_MBOX_U2,
    PERF_MBOX_U3,

    PERF_MBOX_U1_VERIFY_HOST_SIG,
    PERF_MBOX_U1_VERIFY_HOST_SELECTIVE_SIG,
    PERF_MBOX_U1_GEN_DH_SHARED_SECRET,
    PERF_MBOX_U1_VERIFY_WITH_POLICY,
    PERF_MBOX_U1_ADD_INFO_REQ_U,
    PERF_MBOX_U1_ADD_INFO_REQ_S,
    PERF_MBOX_U1_ADD_INFO_REQ_SELECTIVE_S,
    PERF_MBOX_U1_SERVICE_SIGNATURE,
    PERF_MBOX_U1_HASH_SERVICE_OFFER,

    PERF_MBOX_U2_VERIFY_HOST_SIG,
    PERF_MBOX_U2_VERIFY_HOST_SELECTIVE_SIG,
    PERF_MBOX_U2_VERIFY_USER_SIG,
    PERF_MBOX_U2_VERIFY_USER_SELECTIVE_SIG,
    PERF_MBOX_U2_GEN_DH_SHARED_SECRET,
    PERF_MBOX_U2_VERIFY_ACK_U,
    PERF_MBOX_U2_VERIFY_ACK_S,
    PERF_MBOX_U2_VERIFY_ACK_SELECTIVE_S,
    PERF_MBOX_U2_BUILD_PARAM_REM_LIST,
    PERF_MBOX_U2_DEC_SYMM_KEY_DH,
    PERF_MBOX_U2_DEC_SYMM_KEY_RSA,
    PERF_MBOX_U2_DEC_ENDPOINT_SECRET,
    PERF_MBOX_U2_VERIFY_INFO_REQ,
    PERF_MBOX_U2_VERIFY_WITH_POLICY,
    PERF_MBOX_U2_ADD_INFO_REQ_U,
    PERF_MBOX_U2_ADD_INFO_REQ_S,
    PERF_MBOX_U2_ADD_INFO_REQ_SELECTIVE_S,
    PERF_MBOX_U2_SERVICE_SIGNATURE,
    PERF_MBOX_U2_HASH_SERVICE_OFFER,
    PERF_MBOX_U2_REM_PARAMS,

    PERF_MBOX_U3_VERIFY_HOST_SIG,
    PERF_MBOX_U3_VERIFY_HOST_SELECTIVE_SIG,
    PERF_MBOX_U3_VERIFY_USER_SIG,
    PERF_MBOX_U3_VERIFY_USER_SELECTIVE_SIG,
    PERF_MBOX_U3_VERIFY_ACK_U,
    PERF_MBOX_U3_VERIFY_ACK_S,
    PERF_MBOX_U3_VERIFY_ACK_SELECTIVE_S,
    PERF_MBOX_U3_BUILD_PARAM_REM_LIST,
    PERF_MBOX_U3_DEC_SYMM_KEY_DH,
    PERF_MBOX_U3_DEC_SYMM_KEY_RSA,
    PERF_MBOX_U3_DEC_ENDPOINT_SECRET,
    PERF_MBOX_U3_VERIFY_INFO_REQ,
    PERF_MBOX_U3_REM_PARAMS,

    PERF_UPDATE,
    PERF_NOTIFY,
    PERF_VERIFY,
    PERF_BASE,
    PERF_CLOSE_SEND,
    PERF_HANDLE_CLOSE,
    PERF_HANDLE_CLOSE_ACK,
    PERF_CLOSE_COMPLETE,
    PERF_PERF,               // time to stop and write a perf set
    PERF_NEW_CONN,           // test 0
    PERF_NEW_CONN_RESPONDER,           // test 0
    PERF_NEW_UPDATE_CONN,    // time to establish a new connection when a HA already exists
    PERF_NEW_UPDATE_CONN_RESPONDER,    // time to establish a new connection when a HA already exists
    PERF_CONN_REQUEST,       // test 1
    PERF_I_APP_CTX_LOOKUP,         // test 1.1 (the three measurements are tests 1.1.1, 1.1.2 and 1.1.3)
    PERF_R_APP_CTX_LOOKUP,
    PERF_I_USER_CTX_LOOKUP,         // test 1.1 (the three measurements are tests 1.1.1, 1.1.2 and 1.1.3)
    PERF_R_USER_CTX_LOOKUP,
    PERF_I_NETSTAT_LOOKUP,   // tests 1.1.1
    PERF_R_NETSTAT_LOOKUP,
    PERF_I_NETSTAT_CMD,
    PERF_R_NETSTAT_CMD,
    PERF_I_HOST_CTX_LOOKUP,
    PERF_R_HOST_CTX_LOOKUP,
    PERF_I_VERIFY_APPLICATION, // tests 1.1.2
    PERF_R_VERIFY_APPLICATION, // tests 1.1.2
    PERF_I_X509AC_VERIFY_CERT_CHAIN,
    PERF_R_X509AC_VERIFY_CERT_CHAIN,
    PERF_I_LOAD_USER_CERT,
    PERF_R_LOAD_USER_CERT,
    PERF_I_LOAD_USER_NAME,
    PERF_R_LOAD_USER_NAME,
    PERF_I_LOAD_USER_KEY,      // time to load the users key from harddrive
    PERF_R_LOAD_USER_KEY,      // time to load the users key from harddrive
    PERF_I_LOAD_USER_PUBKEY,   // time to load the users public key from harddrive
    PERF_R_LOAD_USER_PUBKEY,   // time to load the users public key from harddrive
    PERF_HASH,
    PERF_SEND_CONN_REQUEST,  // test 1.2
    PERF_VERIFY_USER_SIG,    // test 2.1, 3.1
    PERF_HIPFW_REQ0,
    PERF_HIPFW_REQ1,         // test 2.2
    PERF_HIPFW_REQ2,         // test 3.2
    PERF_HIPFW_REQ3,         // test 4.3
    PERF_HIPD_R2_FINISH,     // time from receiving R2 until sending request to hipfw
    PERF_HIPFW_R2_FINISH,    // time from receiving final request until acceptance of connection
    PERF_HIPD_I3_FINISH,     // time from receiving I3 until sending request to hipfw
    PERF_HIPFW_I3_FINISH,    // time from receiving final request until acceptance of connection
    PERF_IP6TABLES,          // time for setting up ip6table rules
    PERF_I2_VERIFY_USER_PUBKEY,
    PERF_R2_VERIFY_USER_PUBKEY,
    PERF_X509_VERIFY_CERT_CHAIN,
    PERF_MBOX_X509_VERIFY_CERT_CHAIN,
    PERF_X509_VERIFY_CERT_CHAIN_RESPONDER,  // hack
    PERF_HANDLE_CERT_CHAIN_RESPONDER, // hack
    PERF_SEND_CERT_CHAIN,    // time to push out a certificate chain
    PERF_RECEIVE_CERT_CHAIN, // time to receive certificate chain
    PERF_CERTIFICATE_EXCHANGE, // time for additional certificate exchange
    PERF_HANDLE_CERT_CHAIN,  // time to save, verify etc
    PERF_CERT_UP_CERT_ACK,  // time after sending a chain until receiving the ack
    PERF_USER_COMM,          // around tests 2.2, 3.2 and 4.3
    PERF_USER_COMM_UPDATE,   // same as above but during update exchange
    /* The firewall only uses the sensors given above, hence it
     * has a separate PERF_MAX. */
    PERF_MAX_FIREWALL,
    PERF_I2_DH_CREATE,
    PERF_R2_DH_CREATE,
    PERF_SIGN,
    PERF_I1_SEND,
    PERF_STARTUP,

    PERF_R1_VERIFY_HOST_SIG, // time to verify host signature on R1
    PERF_I2_GROUP_SERVICE_OFFERS,
    PERF_I2_LOCATE_MBOX_CERT,
    PERF_I2_HANDLE_UNSIGNED_SERVICE_OFFER,
    PERF_I2_HANDLE_SELECTIVE_SIGNED_OFFER,
    PERF_I2_HANDLE_SIGNED_SERVICE_OFFER,
    PERF_I2_VERIFY_MBOX_SIGN,
    PERF_I2_GEN_SYMM_KEY_SIGNED_OFFER,      // time to load the users key from harddrive
    PERF_I2_ENCRYPT_ENDPOINT_SECRETS,
    PERF_I2_UNSIGNED_SERVICE_ACK,
    PERF_I2_SELECTIVE_SIGNED_SERVICE_ACK,
    PERF_I2_SIGNED_SERVICE_ACK,
    PERF_I2_HASH_SERVICE_OFFER,
    PERF_I2_ENC_SYMM_KEY_INFO_ACK_DH,
    PERF_I2_ENC_SYMM_KEY_INFO_ACK_RSA,
    PERF_I2_HOST_SIGN,       // time to generate host signature on I2
    PERF_I2_SELECTIVE_HOST_SIGN,
    PERF_I2_USER_SIGN,       // time to generate user signature on I2
    PERF_I2_SELECTIVE_USER_SIGN,

    PERF_I2_VERIFY_HOST_SIG, // time to verify host signature on I2
    PERF_I2_VERIFY_SELECTIVE_HOST_SIG, // time to verify selective host signature on I2
    PERF_I2_VERIFY_USER_SIG, // time to verify user signature on I2
    PERF_I2_VERIFY_SELECTIVE_USER_SIG, // time to verify selective user signature on I2
    PERF_R2_GROUP_SERVICE_OFFERS,
    PERF_R2_LOCATE_MBOX_CERT,
    PERF_R2_HANDLE_UNSIGNED_SERVICE_OFFER,
    PERF_R2_HANDLE_SELECTIVE_SIGNED_OFFER,
    PERF_R2_HANDLE_SIGNED_SERVICE_OFFER,
    PERF_R2_VERIFY_MBOX_SIGN,
    PERF_R2_ENCRYPT_ENDPOINT_SECRETS,
    PERF_R2_GEN_SYMM_KEY_SIGNED_OFFER,      // time to load the users key from harddrive
    PERF_R2_UNSIGNED_SERVICE_ACK,
    PERF_R2_SELECTIVE_SIGNED_SERVICE_ACK,
    PERF_R2_SIGNED_SERVICE_ACK,
    PERF_R2_HASH_SERVICE_OFFER,
    PERF_R2_ENC_SYMM_KEY_INFO_ACK_DH,
    PERF_R2_ENC_SYMM_KEY_INFO_ACK_RSA,
    PERF_R2_HOST_SIGN,       // time to generate host signature on R2
    PERF_R2_SELECTIVE_HOST_SIGN,
    PERF_R2_USER_SIGN,       // time to generate user signature on R2
    PERF_R2_SELECTIVE_USER_SIGN,

    PERF_R2_VERIFY_HOST_SIG, // time to verify host signature on R2
    PERF_R2_VERIFY_USER_SIG, // time to verify user signature on R2
    PERF_R2_VERIFY_SELECTIVE_HOST_SIG,
    PERF_R2_VERIFY_SELECTIVE_USER_SIG, // time to verify user signature on R2
    PERF_I3_HOST_SIGN,       // time to generate host signature on I3
    PERF_I3_USER_SIGN,       // time to generate user signature on I3
    PERF_I3_VERIFY_HOST_SIG, // time to verify user signature on I3
    PERF_I3_VERIFY_USER_SIG, // time to verify user signature on I3
    PERF_UPDATE_HOST_SIGN,   // time to sign an update packet
    PERF_UPDATE_VERIFY_HOST_SIG, // time to verify user signature on UPDATE

    PERF_CONN_U1_VERIFY_HMAC,       // time to verify hmac on connection UPDATE 1
    PERF_CONN_U1_HMAC,              // time to generate hmac on connection UPDATE 1
    PERF_CONN_U2_VERIFY_HMAC,       // time to verify hmac on connection UPDATE 2
    PERF_CONN_U2_HMAC,              // time to generate hmac on UPDATE 2
    PERF_CONN_U2_VERIFY_SELECTIVE_HMAC,
    PERF_CONN_U2_SELECTIVE_HMAC,
    PERF_CONN_U3_VERIFY_HMAC,       // time to verify hmac on connection UPDATE 3
    PERF_CONN_U3_HMAC,              // time to generate hmac on UPDATE 3
    PERF_CONN_U3_VERIFY_SELECTIVE_HMAC,
    PERF_CONN_U3_SELECTIVE_HMAC,

    PERF_CONN_U1_VERIFY_USER_SIG,   // time to verify signature on connection UPDATE 2
    PERF_CONN_U1_USER_SIGN,         // time to verify signature on connection UPDATE 1
    PERF_CONN_U2_VERIFY_USER_SIG,   // time to verify signature on connection UPDATE 2
    PERF_CONN_U2_USER_SIGN,         // time to generate host signature on UPDATE 2
    PERF_CONN_U3_VERIFY_USER_SIG,   // time to verify signature on connection UPDATE 2
    PERF_CONN_U3_USER_SIGN,         // time to generate iuser signature on UPDATE 3

    PERF_CONN_U1_VERIFY_SELECTIVE_USER_SIG,   // time to verify signature on connection UPDATE 2
    PERF_CONN_U1_SELECTIVE_USER_SIGN,         // time to verify signature on connection UPDATE 1
    PERF_CONN_U2_VERIFY_SELECTIVE_USER_SIG,   // time to verify signature on connection UPDATE 2
    PERF_CONN_U2_SELECTIVE_USER_SIGN,         // time to generate host signature on UPDATE 2
    PERF_CONN_U3_VERIFY_SELECTIVE_USER_SIG,   // time to verify signature on connection UPDATE 2
    PERF_CONN_U3_SELECTIVE_USER_SIGN,         // time to generate iuser signature on UPDATE 3

    PERF_CONN_U1_VERIFY_HOST_SIGN,         // time to verify signature on connection UPDATE 1
    PERF_CONN_U1_HOST_SIGN,         // time to verify signature on connection UPDATE 1
    PERF_CONN_U2_VERIFY_HOST_SIGN,         // time to generate host signature on UPDATE 2
    PERF_CONN_U2_HOST_SIGN,         // time to generate host signature on UPDATE 2
    PERF_CONN_U3_VERIFY_HOST_SIGN,         // time to generate host signature on UPDATE 3
    PERF_CONN_U3_HOST_SIGN,         // time to generate host signature on UPDATE 3

    PERF_CONN_U2_VERIFY_SELECTIVE_HOST_SIGN, // time to verify selective signature on connection UPDATE 2
    PERF_CONN_U2_SELECTIVE_HOST_SIGN,       // time to generate selective signature on connection UPDATE 2
    PERF_CONN_U3_VERIFY_SELECTIVE_HOST_SIGN, // time to verify selective signature on connection UPDATE 3
    PERF_CONN_U3_SELECTIVE_HOST_SIGN,       // time to generate selective signature on connection UPDATE 3

    PERF_CONN_U1_DIFFIE_HELLMAN, // time to generate hmac on connection UPDATE 1
    PERF_CONN_U2_DIFFIE_HELLMAN, // time to generate hmac on UPDATE 2

    PERF_CONN_U1_HANDLE_UNSIGNED_SERVICE_OFFER,
    PERF_CONN_U2_HANDLE_UNSIGNED_SERVICE_OFFER,
    PERF_CONN_U1_HANDLE_SIGNED_OFFER,
    PERF_CONN_U2_HANDLE_SIGNED_OFFER,
    PERF_CONN_U1_HANDLE_SELECTIVE_SIGNED_OFFER,
    PERF_CONN_U2_HANDLE_SELECTIVE_SIGNED_OFFER,
    PERF_CONN_U1_LOCATE_MBOX_CERT,
    PERF_CONN_U2_LOCATE_MBOX_CERT,

    PERF_CONN_U2_UNSIGNED_ACK,
    PERF_CONN_U3_UNSIGNED_ACK,
    PERF_CONN_U2_SIGNED_ACK,
    PERF_CONN_U3_SIGNED_ACK,
    PERF_CONN_U2_SELECTIVE_SIGNED_ACK,
    PERF_CONN_U3_SELECTIVE_SIGNED_ACK,

    PERF_CONN_U1_GROUP_SERVICE_OFFERS,
    PERF_CONN_U2_GROUP_SERVICE_OFFERS,

    PERF_CONN_U2_VERIFY_MBOX_SIGN,
    PERF_CONN_U2_GEN_SYMM_KEY_SIGNED_OFFER,      // time to load the users key from harddrive
    PERF_CONN_U2_ENCRYPT_ENDPOINT_SECRETS,
    PERF_CONN_U2_HASH_SERVICE_OFFER,
    PERF_CONN_U2_ENC_SYMM_KEY_INFO_ACK_DH,
    PERF_CONN_U2_ENC_SYMM_KEY_INFO_ACK_RSA,

    PERF_CONN_U3_VERIFY_MBOX_SIGN,
    PERF_CONN_U3_GEN_SYMM_KEY_SIGNED_OFFER,      // time to load the users key from harddrive
    PERF_CONN_U3_ENCRYPT_ENDPOINT_SECRETS,
    PERF_CONN_U3_HASH_SERVICE_OFFER,
    PERF_CONN_U3_ENC_SYMM_KEY_INFO_ACK_DH,
    PERF_CONN_U3_ENC_SYMM_KEY_INFO_ACK_RSA,

    PERF_CONN_U_I_APP_CTX_LOOKUP,   // test 1.1 (the three measurements are tests 1.1.1, 1.1.2 and 1.1.3)
    PERF_CONN_U_R_APP_CTX_LOOKUP,
    PERF_CONN_U_I_USER_CTX_LOOKUP,  // test 1.1 (the three measurements are tests 1.1.1, 1.1.2 and 1.1.3)
    PERF_CONN_U_R_USER_CTX_LOOKUP,
    PERF_CONN_U_I_NETSTAT_LOOKUP,   // tests 1.1.1
    PERF_CONN_U_R_NETSTAT_LOOKUP,
    PERF_CONN_U_I_NETSTAT_CMD,
    PERF_CONN_U_R_NETSTAT_CMD,
    PERF_CONN_U_I_HOST_CTX_LOOKUP,
    PERF_CONN_U_R_HOST_CTX_LOOKUP,
    PERF_CONN_U_I_VERIFY_APPLICATION, // tests 1.1.2
    PERF_CONN_U_R_VERIFY_APPLICATION, // tests 1.1.2
    PERF_CONN_U_I_X509AC_VERIFY_CERT_CHAIN,
    PERF_CONN_U_R_X509AC_VERIFY_CERT_CHAIN,
    PERF_CONN_U_I_LOAD_USER_KEY,      // time to load the users key from harddrive
    PERF_CONN_U_R_LOAD_USER_KEY,      // time to load the users key from harddrive
    PERF_CONN_U_I_LOAD_USER_PUBKEY,   // time to load the users public key from harddrive
    PERF_CONN_U_R_LOAD_USER_PUBKEY,   // time to load the users public key from harddrive
    PERF_CONN_U_I_LOAD_USER_CERT,
    PERF_CONN_U_R_LOAD_USER_CERT,
    PERF_CONN_U_I_LOAD_USER_NAME,
    PERF_CONN_U_R_LOAD_USER_NAME,

    PERF_COMPLETE_UPDATE_EX,

    PERF_NOTIFY_VERIFY_HOST_SIG, // time to verify signature on NOTIFY
    PERF_ECDSA_VERIFY_IMPL,     // time for openssl ecdsa do verify
    PERF_ECDSA_SIGN_IMPL,       // time for openssl ecdsa do sign
    PERF_RSA_VERIFY_IMPL,       // time for openssl ecdsa do verify
    PERF_RSA_SIGN_IMPL,         // time for openssl ecdsa do sign
    PERF_TRIGGER_CONN,          // hipd side of test SEND_CONN_REQUEST
    PERF_TRIGGER_UPDATE,
    PERF_COMPLETE_BEX,          // hipd side of test SEND_CONN_REQUEST
    PERF_I2_HMAC,                       // HMAC
    PERF_R2_HMAC,                       // HMAC
    PERF_I2_SELECTIVE_HMAC,             // Selective HMAC
    PERF_R2_SELECTIVE_HMAC,             // Selective HMAC
    PERF_I2_VERIFY_HMAC,                // Verify HMAC
    PERF_R2_VERIFY_HMAC,                // Verify HMAC
    PERF_I2_VERIFY_SELECTIVE_HMAC,      // Verify Selective HMAC
    PERF_R2_VERIFY_SELECTIVE_HMAC,      // Verify Selective HMAC

    /* Number of sensors for the HIP daemon. */
    PERF_MAX
};

struct perf_set *perf_set;

#endif /* HIP_LIB_CORE_PERFORMANCE_H */
