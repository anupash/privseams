/*
 * signaling_netstat_wrapper.c
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/common.h"

#include "signaling_netstat_api.h"

/* MAX = sizeof(netstat -tpn | grep :{port} | grep :{port}) < 60 */
#define CALLBUF_SIZE            60
/* MAX = sizeof(/proc/{port}/exe) <= 16 */
#define SYMLINKBUF_SIZE         16
/* MAX = ? */
#define PATHBUF_SIZE            200

// Netstat format widths (derived from netstat source code)
#define NETSTAT_SIZE_PROTO      7
#define NETSTAT_SIZE_RECV_SEND  7
#define NETSTAT_SIZE_OUTPUT     160
#define NETSTAT_SIZE_STATE      12
#define NETSTAT_SIZE_PROGNAME   20
#define NETSTAT_SIZE_ADDR_v6    50

int signaling_netstat_get_application_context(uint16_t srcport, uint16_t destport) {
    FILE *fp;
    int err = 0, UNUSED scanerr;
    char *res;
    char callbuf[CALLBUF_SIZE];
    char symlinkbuf[SYMLINKBUF_SIZE];
    char readbuf[NETSTAT_SIZE_OUTPUT];
    char pathbuf[PATHBUF_SIZE];

    // variables for parsing
    char proto[NETSTAT_SIZE_PROTO];
    char unused[NETSTAT_SIZE_RECV_SEND];
    char remote_addr[NETSTAT_SIZE_ADDR_v6];
    char local_addr[NETSTAT_SIZE_ADDR_v6];
    char state[NETSTAT_SIZE_STATE];
    char progname[NETSTAT_SIZE_PROGNAME];
    int pid = 0;
    UNUSED int local_port = 0, remote_port = 0;

    memset(proto, 0, NETSTAT_SIZE_PROTO);
    memset(unused, 0, NETSTAT_SIZE_RECV_SEND);
    memset(remote_addr, 0, NETSTAT_SIZE_ADDR_v6);
    memset(local_addr, 0, NETSTAT_SIZE_ADDR_v6);
    memset(state, 0, NETSTAT_SIZE_STATE);
    memset(progname, 0, NETSTAT_SIZE_PROGNAME);

    // prepare call to netstat
    memset(callbuf, 0, CALLBUF_SIZE);
    sprintf(callbuf, "netstat -tpnW | grep :%d | grep :%d", srcport, destport);

    // make call to netstat
    memset(&readbuf[0], 0, NETSTAT_SIZE_OUTPUT);
    HIP_IFEL(!(fp = popen(callbuf, "r")), -1, "Failed to make call to nestat.\n");
    res = fgets(&readbuf[0], NETSTAT_SIZE_OUTPUT, fp);
    pclose(fp);
    if(res == NULL) {
        HIP_DEBUG("Got no output from netstat.\n");
        goto out_err;
    }

    // parse output
    scanerr = sscanf(readbuf, "%s %s %s %s %s %s %d/%s",
            proto, unused, unused, local_addr, remote_addr, state, &pid, progname);
    HIP_DEBUG("Found program %s (%d) on a %s connection from: \n", progname, pid, proto);
    HIP_DEBUG("\t from:\t %s\n", local_addr);
    HIP_DEBUG("\t to:\t %s\n", remote_addr);

    // determine path to application binary from /proc/{pid}/exe
    memset(symlinkbuf, 0, SYMLINKBUF_SIZE);
    memset(pathbuf, 0, PATHBUF_SIZE);
    sprintf(symlinkbuf, "/proc/%i/exe", pid);
    scanerr = readlink(symlinkbuf, pathbuf, PATHBUF_SIZE);
    HIP_DEBUG("Found application binary at: %s \n", pathbuf);

out_err:

    return err;
}

