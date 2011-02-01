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
    PERF_R1,
    PERF_I2,
    PERF_R2,
    PERF_UPDATE,
    PERF_VERIFY,
    PERF_BASE,
    PERF_CLOSE_SEND,
    PERF_HANDLE_CLOSE,
    PERF_HANDLE_CLOSE_ACK,
    PERF_CLOSE_COMPLETE,
    PERF_DSA_VERIFY_IMPL,
    PERF_RSA_VERIFY_IMPL,
    PERF_ECDSA_VERIFY_IMPL,  // test 2.1.1

    PERF_NEW_CONN,           // test 0
    PERF_CONN_REQUEST,       // test 1
    PERF_CTX_LOOKUP,         // test 1.1 (the three measurements are tests 1.1.1, 1.1.2 and 1.1.3)
    PERF_SEND_CONN_REQUEST,  // test 1.2
    PERF_HANDLE_I2,          // test 2
    PERF_HANDLE_R2,          // test 3
    PERF_VERIFY_USER_SIG,    // test 2.1, 3.1
    PERF_HIPFW_REQ1,         // test 2.2
    PERF_HIPFW_REQ2,         // test 3.2
    PERF_HIPFW_REQ3,         // test 4.3
    /* The firewall only uses the sensors given above, hence it
     * has a separate PERF_MAX. */
    PERF_MAX_FIREWALL,
    PERF_DH_CREATE,
    PERF_SIGN,
    PERF_DSA_SIGN_IMPL,
    PERF_I1_SEND,
    PERF_RSA_SIGN_IMPL,
    PERF_STARTUP,

    PERF_ECDSA_SIGN_IMPL,
    PERF_TRIGGER_CONN,       // hipd side of test SEND_CONN_REQUEST
    PERF_USER_COMM,          // arount tests 2.2, 3.2 and 4.3

    /* Number of sensors for the HIP daemon. */
    PERF_MAX
};

struct perf_set *perf_set;

#endif /* HIP_LIB_CORE_PERFORMANCE_H */
