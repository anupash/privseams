#ifndef performance_h
#define performance_h

/*
 * Primitive performance measurement
 *
 * Authors:
 * - Tobias Heer <heer@tobibox.de>
 */

#include <stdio.h>

/*! This performace set holds all measurements */
struct perf_set {
    /*! \brief A pointer to names of output files */
    FILE **         files;
    /*! \brief A list of names of the perf sets. */
    char **         names;
    /*! \brief A list timeval time structs. */
    struct timeval *times;
    /*! \brief A list of measured results. */
    double *        result;
    /*! \brief The number of perf sets. */
    int             num_files;
    /*! \brief A linecount.. */
    int *           linecount;
    /*! \brief Are the necessary files opened? 1=TRUE, 0=FALSE. */
    int             files_open;
    /*! \brief Are measurements running? This is an integer field of the length num_files. */
    int *           running;
    /*! \brief Are the measurements writable (completed)? This is an integer field of the length num_files. */
    int *           writable;
};

typedef struct perf_set perf_set_t;

int hip_perf_enabled(void);
perf_set_t *hip_perf_create(int num);
int hip_perf_set_name(perf_set_t *perf_set,  int slot, const char *name);
int hip_perf_open(perf_set_t *perf_set);
void hip_perf_start_benchmark(perf_set_t *perf_set, int slot);
void hip_perf_stop_benchmark(perf_set_t *perf_set, int slot);
int hip_perf_write_benchmark(perf_set_t *perf_set, int slot);
int hip_perf_close(perf_set_t *perf_set);
void hip_perf_destroy(perf_set_t *perf_set);


#define PERF_I1                         0
#define PERF_R1                         1
#define PERF_I2                         2
#define PERF_R2                         3
#define PERF_VERIFY                     4
#define PERF_BASE                       5
#define PERF_ALL                        6
#define PERF_UPDATE_COMPLETE            7
#define PERF_CLOSE_SEND                 8
#define PERF_HANDLE_CLOSE               9
#define PERF_HANDLE_CLOSE_ACK           10
#define PERF_HANDLE_UPDATE_1            11
#define PERF_CLOSE_COMPLETE             12
#define PERF_DSA_VERIFY_IMPL            13
#define PERF_RSA_VERIFY_IMPL            14

/* The firewall only uses the sensors given above, hence it has a separate PERF_MAX. */
#define PERF_MAX_FIREWALL               15

#define PERF_DH_CREATE                  15
#define PERF_SIGN                       16
#define PERF_DSA_SIGN_IMPL              17
#define PERF_I1_SEND                    18
#define PERF_UPDATE_SEND                19
#define PERF_VERIFY_UPDATE              20
#define PERF_HANDLE_UPDATE_ESTABLISHED  21
#define PERF_HANDLE_UPDATE_REKEYING     22
#define PERF_UPDATE_FINISH_REKEYING     23
#define PERF_HANDLE_UPDATE_2            24
#define PERF_RSA_SIGN_IMPL              25

/* Number of sensors for the HIP daemon. */
#define PERF_MAX                        26

perf_set_t *perf_set;

#endif
