/*
 * signaling_netstat_wrapper.c
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/core/debug.h"
#include "lib/core/ife.h"

#include "signaling_netstat_api.h"

#define CALLBUF_SIZE 60
#define READBUF_SIZE 120

int signaling_netstat_get_application_context(uint16_t srcport, uint16_t destport) {
    FILE *fp;
    int err = 0;
    char *res;
    char callbuf[CALLBUF_SIZE];
    char readbuf[READBUF_SIZE];

    // prepare call to netstat
    memset(callbuf, 0, CALLBUF_SIZE);
    sprintf(callbuf, "netstat -tpn | grep :%d | grep :%d", srcport, destport);

    // make call to netstat
    memset(&readbuf[0], 0, READBUF_SIZE);
    HIP_IFEL(!(fp = popen(callbuf, "r")), -1, "Failed to make call to nestat.\n");
    res = fgets(&readbuf[0], READBUF_SIZE, fp);
    if(res != NULL) {
        HIP_DEBUG("NETSTAT: %s", readbuf);
    }

out_err:

    pclose(fp);
    return err;
}

