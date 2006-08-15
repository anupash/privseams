#ifndef HIPCONF_H
#define HIPCONF_H

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include <hip.h>
#include <sysexits.h>

#include <assert.h>

#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "debug.h"
#include "crypto.h"
#include "builder.h"

/* 0 is reserved */
#define ACTION_ADD 1
#define ACTION_DEL 2
#define ACTION_NEW 3
#define ACTION_HIP 4
#define ACTION_SET 5
#define ACTION_INC 6
#define ACTION_DEC 7
#define ACTION_GET 8
#define ACTION_RUN 9

#define ACTION_MAX 10 /* exclusive */

/* 0 is reserved */
#define TYPE_HI      1
#define TYPE_MAP     2
#define TYPE_RST     3
#define TYPE_RVS     4
#define TYPE_BOS     5
#define TYPE_PUZZLE  6
#define TYPE_NAT     7
#define TYPE_OPP     8
#define TYPE_ESCROW  9
#define TYPE_SERVICE 10
#define TYPE_RVS_NEW 11
#define TYPE_RUN     12
#define TYPE_MAX     13 /* exclusive */

/* for handle_hi() only */
#define OPT_HI_TYPE 0
#define OPT_HI_FMT  1
#define OPT_HI_FILE 2

int handle_hi(struct hip_common *, int type, const char **opt, int optc);
int handle_map(struct hip_common *, int type, const char **opt, int optc);
int handle_rst(struct hip_common *, int type, const char **opt, int optc);
int handle_bos(struct hip_common *, int type, const char **opt, int optc);
int handle_rvs(struct hip_common *, int type, const char **opt, int optc);
int handle_rvs_new(struct hip_common *msg, int action, const char **opt, int optc);
int handle_del(struct hip_common *, int type, const char **opt, int optc);
int handle_nat(struct hip_common *, int type, const char **opt, int optc);
int handle_puzzle(struct hip_common *, int type, const char **opt, int optc);
int handle_opp(struct hip_common *msg, int action, const char *opt[], int optc);
int handle_escrow(struct hip_common *msg, int action, const char *opt[], int optc);
int handle_service(struct hip_common *msg, int action, const char *opt[], int optc);
int get_action(char *action);
int get_type(char *type);

#endif /* HIPCONF */
