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

#include <net/hip.h>
#include <sysexits.h>

#include <assert.h>

#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/pem.h>

#include "tools/debug.h"
#include "../linux/net/ipv6/hip/builder.h"
#include "crypto.h"

/* 0 is reserved */
#define ACTION_ADD 1
#define ACTION_DEL 2
#define ACTION_RST 3
#define ACTION_NEW 4
#define ACTION_MAX 5 /* exclusive */

/* 0 is reserved */
#define TYPE_HI 1
#define TYPE_MAP 2
#define TYPE_RST 3
#define TYPE_MAX 4 /* exclusive */

/* for handle_hi() only */
#define OPT_HI_TYPE 0
#define OPT_HI_FMT  1
#define OPT_HI_FILE 2

int handle_hi(struct hip_common *, int type, const char **opt, int optc);
int handle_map(struct hip_common *, int type, const char **opt, int optc);
int handle_rst(struct hip_common *, int type, const char **opt, int optc);
int get_action(char *action);
int get_type(char *type);

#endif /* HIPCONF */
