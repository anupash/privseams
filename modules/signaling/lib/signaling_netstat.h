#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <paths.h>
#include <pwd.h>
#include <getopt.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "net-support.h"
#include "pathnames.h"
#include "version.h"

#include "lib/core/debug.h"
#include "signaling_oslayer.h"

#define I18N 1

/*
 *
 * Protocol Families.
 *
 */
#define HAVE_AFUNIX 1
#define HAVE_AFINET 1
#define HAVE_AFINET6 1
#define HAVE_AFIPX 1
#define HAVE_AFATALK 1
#define HAVE_AFAX25 1
#define HAVE_AFNETROM 1
#define HAVE_AFROSE 1
#define HAVE_AFX25 1
#define HAVE_AFECONET 1
#define HAVE_AFDECnet 1
#define HAVE_AFASH 1

/*
 *
 * Device Hardware types.
 *
 */
#define HAVE_HWETHER 1
#define HAVE_HWARC 1
#define HAVE_HWSLIP 1
#define HAVE_HWPPP 1
#define HAVE_HWTUNNEL 1
#define HAVE_HWSTRIP 1
#define HAVE_HWTR 1
#define HAVE_HWAX25 1
#define HAVE_HWROSE 1
#define HAVE_HWNETROM 1
#define HAVE_HWX25 1
#define HAVE_HWFR 1
#define HAVE_HWSIT 1
#define HAVE_HWFDDI 1
#define HAVE_HWHIPPI 1
#define HAVE_HWASH 1
#define HAVE_HWHDLCLAPB 1
#define HAVE_HWIRDA 1
#define HAVE_HWEC 1
#define HAVE_HWEUI64 1

/*
 *
 * Other Features.
 *
 */
#define HAVE_FW_MASQUERADE 1
#define HAVE_IP_TOOLS 1
#define HAVE_MII 1

#include "intl.h"
#include "sockets.h"
//#include "interface.h"
#include "util.h"
#include "proc.h"


#define PROGNAME_WIDTH 20

#if !defined(s6_addr32) && defined(in6a_words)
#define s6_addr32 in6a_words    /* libinet6			*/
#endif


typedef enum {
    SS_FREE = 0,                /* not allocated                */
    SS_UNCONNECTED,             /* unconnected to any socket    */
    SS_CONNECTING,              /* in process of connecting     */
    SS_CONNECTED,               /* connected to socket          */
    SS_DISCONNECTING            /* in process of disconnecting  */
} socket_state;

#define SO_ACCEPTCON    (1 << 16) /* performed a listen           */
#define SO_WAITDATA     (1 << 17) /* wait data to read            */
#define SO_NOSPACE      (1 << 18) /* no space to write            */

#define DFLT_AF "inet"

#define FEATURE_NETSTAT
//#include "lib/net-features.h"

//char *Release = "release", *Version = "netstat 1.42 (2001-04-15)", *Signature = "Fred Baumgarten, Alan Cox, Bernd Eckenfels, Phil Blundell, Tuan Hoang and others";


#define E_READ  -1
#define E_IOCTL -3



FILE *procinfo;

#define INFO_GUTS1(file, name, proc, src_port, dst_port)    \
    procinfo = proc_fopen((file));                        \
    if (procinfo == NULL) {                               \
        if (errno != ENOENT) {                              \
            perror((file));                                   \
            return -1;                                        \
        }                                                   \
        if (flag_arg || flag_ver) {                           \
            ESYSNOT("netstat", (name)); }                       \
        if (flag_arg) {                                       \
            rc = 1; }                                           \
    } else {                                              \
        do {                                                \
            if (fgets(buffer, sizeof(buffer), procinfo)) {      \
                (proc) (lnr++, buffer, src_port, dst_port); }      \
        } while (!feof(procinfo));                          \
        fclose(procinfo);                                   \
    }

#if HAVE_AFINET6
#define INFO_GUTS2(file, proc, src_port, dst_port)         \
    lnr      = 0;                                              \
    procinfo = proc_fopen((file));                        \
    if (procinfo != NULL) {                               \
        do {                                                \
            if (fgets(buffer, sizeof(buffer), procinfo)) {      \
                (proc) (lnr++, buffer, src_port, dst_port); }      \
        } while (!feof(procinfo));                          \
        fclose(procinfo);                                   \
    }
#else
#define INFO_GUTS2(file, proc, src_port, dst_port)
#endif

#define INFO_GUTS3                                      \
    return rc;

#define INFO_GUTS6(file, file6, name, src_port, dst_port, proc) \
    char buffer[8192];                                     \
    int rc  = 0;                                            \
    int lnr = 0;                                           \
    if (!flag_arg || flag_inet) {                          \
        INFO_GUTS1(file, name, proc, src_port, dst_port)        \
    }                                                      \
    if (!flag_arg || flag_inet6) {                         \
        INFO_GUTS2(file6, proc, src_port, dst_port)            \
    }                                                      \
    INFO_GUTS3

#define INFO_GUTS(file, name, proc, src_port, dst_port)     \
    char buffer[8192];                                     \
    int rc  = 0;                                            \
    int lnr = 0;                                           \
    INFO_GUTS1(file, name, proc, src_port, dst_port)           \
    INFO_GUTS3

#define PROGNAME_WIDTHs PROGNAME_WIDTH1(PROGNAME_WIDTH)
#define PROGNAME_WIDTH1(s) PROGNAME_WIDTH2(s)
#define PROGNAME_WIDTH2(s) # s

#define PRG_HASH_SIZE 211

#define PRG_HASHIT(x) ((x) % PRG_HASH_SIZE)




#define PROGNAME_BANNER "PID/Program name"

#define print_progname_banner() do { if (flag_prg) { printf("%-" PROGNAME_WIDTHs "s", " " PROGNAME_BANNER); } } while (0)

#define PRG_LOCAL_ADDRESS "local_address"
#define PRG_INODE        "inode"
#define PRG_SOCKET_PFX    "socket:["
#define PRG_SOCKET_PFXl (strlen(PRG_SOCKET_PFX))
#define PRG_SOCKET_PFX2   "[0000]:"
#define PRG_SOCKET_PFX2l  (strlen(PRG_SOCKET_PFX2))


#ifndef LINE_MAX
#define LINE_MAX 4096
#endif

#define PATH_PROC               "/proc"
#define PATH_FD_SUFF        "fd"
#define PATH_FD_SUFFl       strlen(PATH_FD_SUFF)
#define PATH_PROC_X_FD      PATH_PROC "/%s/" PATH_FD_SUFF
#define PATH_CMDLINE        "cmdline"
#define PATH_CMDLINEl       strlen(PATH_CMDLINE)
/* NOT working as of glibc-2.0.7: */
#undef  DIRENT_HAVE_D_TYPE_WORKS

int netstat_info_tpneW(int src_port, int dst_port, struct system_app_context *ctx, uint8_t listening);

struct in6_addr_own {
    uint32_t u6_addr32[4];
};
