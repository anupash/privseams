/**
 * @file
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
 *
 * Credits:
 * NET-TOOLS    A collection of programs that form the base set of the
 *              NET-3 Networking Distribution for the LINUX operating
 *              system.
 *
 * Version:     $Id: netstat.c,v 1.55 2007/12/01 19:00:40 ecki Exp $
 *
 *
 * @author Anupam Ashish <anupam.ashish@rwth-aachen.de>
 *
 */

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

#define HAVE_AFINET 1
#define HAVE_AFINET6 1

#include "signaling_netstat.h"

int flag_int = 0;
int flag_rou = 0;
int flag_mas = 0;
int flag_sta = 0;

int flag_all  = 0;
int flag_lst  = 0;
int flag_cnt  = 0;
int flag_deb  = 0;
int flag_not  = 0;
int flag_cf   = 0;
int flag_opt  = 0;
int flag_raw  = 0;
int flag_tcp  = 0;
int flag_udp  = 0;
int flag_igmp = 0;
int flag_rom  = 0;
int flag_exp  = 1;
int flag_wide = 0;
int flag_prg  = 0;
int flag_arg  = 0;
int flag_ver  = 0;

static struct prg_node {
    struct prg_node *next;
    unsigned long    inode;
    char             name[PROGNAME_WIDTH];
} *prg_hash[PRG_HASH_SIZE];

static char prg_cache_loaded = 0;

static struct system_app_context *sys_ctx;

static void prg_cache_add(unsigned long inode, char *name)
{
    unsigned          hi = PRG_HASHIT(inode);
    struct prg_node **pnp, *pn;

    prg_cache_loaded = 2;
    for (pnp = prg_hash + hi; (pn = *pnp); pnp = &pn->next) {
        if (pn->inode == inode) {
            /* Some warning should be appropriate here
             * as we got multiple processes for one i-node */
            return;
        }
    }
    if (!(*pnp = malloc(sizeof(**pnp)))) {
        return;
    }
    pn        = *pnp;
    pn->next  = NULL;
    pn->inode = inode;
    if (strlen(name) > sizeof(pn->name) - 1) {
        name[sizeof(pn->name) - 1] = '\0';
    }
    strcpy(pn->name, name);
}

static const char *prg_cache_get(unsigned long inode)
{
    unsigned         hi = PRG_HASHIT(inode);
    struct prg_node *pn;

    for (pn = prg_hash[hi]; pn; pn = pn->next) {
        if (pn->inode == inode) {
            return pn->name;
        }
    }
    return '\0';
}

static void prg_cache_clear(void)
{
    struct prg_node **pnp, *pn;

    if (prg_cache_loaded == 2) {
        for (pnp = prg_hash; pnp < prg_hash + PRG_HASH_SIZE; pnp++) {
            while ((pn = *pnp)) {
                *pnp = pn->next;
                free(pn);
            }
        }
    }
    prg_cache_loaded = 0;
}

static int extract_type_1_socket_inode(const char lname[], unsigned long *inode_p)
{
    /* If lname is of the form "socket:[12345]", extract the "12345"
     * as *inode_p.  Otherwise, return -1 as *inode_p.
     */

    if (strlen(lname) < PRG_SOCKET_PFXl + 3) {
        return -1;
    }

    if (memcmp(lname, PRG_SOCKET_PFX, PRG_SOCKET_PFXl)) {
        return -1;
    }
    if (lname[strlen(lname) - 1] != ']') {
        return -1;
    }

    {
        char      inode_str[strlen(lname + 1)]; /* e.g. "12345" */
        const int inode_str_len = strlen(lname) - PRG_SOCKET_PFXl - 1;
        char     *serr;

        strncpy(inode_str, lname + PRG_SOCKET_PFXl, inode_str_len);
        inode_str[inode_str_len] = '\0';
        *inode_p                 = strtoul(inode_str, &serr, 0);
        if (!serr || *serr) {
            return -1;
        }
    }
    return 0;
}

static int extract_type_2_socket_inode(const char lname[], unsigned long *inode_p)
{
    /* If lname is of the form "[0000]:12345", extract the "12345"
     * as *inode_p.  Otherwise, return -1 as *inode_p.
     */

    if (strlen(lname) < PRG_SOCKET_PFX2l + 1) {
        return -1;
    }
    if (memcmp(lname, PRG_SOCKET_PFX2, PRG_SOCKET_PFX2l)) {
        return -1;
    }

    {
        char *serr;

        *inode_p = strtoul(lname + PRG_SOCKET_PFX2l, &serr, 0);
        if (!serr || *serr) {
            return -1;
        }
    }
    return 0;
}

static void prg_cache_load(void)
{
    char           line[LINE_MAX], eacces = 0;
    int            procfdlen, fd, cmdllen, lnamelen;
    char           lname[30], cmdlbuf[512], finbuf[PROGNAME_WIDTH];
    unsigned long  inode;
    const char    *cs, *cmdlp;
    DIR           *dirproc = NULL, *dirfd = NULL;
    struct dirent *direproc, *direfd;

    if (prg_cache_loaded || !flag_prg) {
        return;
    }
    prg_cache_loaded             = 1;
    cmdlbuf[sizeof(cmdlbuf) - 1] = '\0';
    if (!(dirproc = opendir(PATH_PROC))) {
        goto fail;
    }
    while (errno = 0, direproc = readdir(dirproc)) {
#ifdef DIRENT_HAVE_D_TYPE_WORKS
        if (direproc->d_type != DT_DIR) {
            continue;
        }
#endif
        for (cs = direproc->d_name; *cs; cs++) {
            if (!isdigit(*cs)) {
                break;
            }
        }
        if (*cs) {
            continue;
        }
        procfdlen = snprintf(line, sizeof(line), PATH_PROC_X_FD, direproc->d_name);
        if (procfdlen <= 0 || procfdlen >= (int) sizeof(line) - 5) {
            continue;
        }
        errno = 0;
        dirfd = opendir(line);
        if (!dirfd) {
            if (errno == EACCES) {
                eacces = 1;
            }
            continue;
        }
        line[procfdlen] = '/';
        cmdlp           = NULL;
        while ((direfd = readdir(dirfd))) {
#ifdef DIRENT_HAVE_D_TYPE_WORKS
            if (direfd->d_type != DT_LNK) {
                continue;
            }
#else
            /* Skip . and .. */
            if (!isdigit(direfd->d_name[0])) {
                continue;
            }
#endif
            if (procfdlen + 1 + strlen(direfd->d_name) + 1 > sizeof(line)) {
                continue;
            }
            memcpy(line + procfdlen - PATH_FD_SUFFl, PATH_FD_SUFF "/",
                   PATH_FD_SUFFl + 1);
            strcpy(line + procfdlen + 1, direfd->d_name);
            lnamelen        = readlink(line, lname, sizeof(lname) - 1);
            lname[lnamelen] = '\0';  /*make it a null-terminated string*/

            if (extract_type_1_socket_inode(lname, &inode) < 0) {
                if (extract_type_2_socket_inode(lname, &inode) < 0) {
                    continue;
                }
            }

            if (!cmdlp) {
                if (procfdlen - PATH_FD_SUFFl + PATH_CMDLINEl >=
                    sizeof(line) - 5) {
                    continue;
                }
                strcpy(line + procfdlen - PATH_FD_SUFFl, PATH_CMDLINE);
                fd = open(line, O_RDONLY);
                if (fd < 0) {
                    continue;
                }
                cmdllen = read(fd, cmdlbuf, sizeof(cmdlbuf) - 1);
                if (close(fd)) {
                    continue;
                }
                if (cmdllen == -1) {
                    continue;
                }
                if (cmdllen < (int) sizeof(cmdlbuf) - 1) {
                    cmdlbuf[cmdllen] = '\0';
                }
                if ((cmdlp = strrchr(cmdlbuf, '/'))) {
                    cmdlp++;
                } else {
                    cmdlp = cmdlbuf;
                }
            }

            snprintf(finbuf, sizeof(finbuf), "%s/%s", direproc->d_name, cmdlp);
            prg_cache_add(inode, finbuf);
        }
        closedir(dirfd);
        dirfd = NULL;
    }
    if (dirproc) {
        closedir(dirproc);
    }
    if (dirfd) {
        closedir(dirfd);
    }
    if (!eacces) {
        return;
    }
    if (prg_cache_loaded == 1) {
fail:
        HIP_ERROR(_("(No info could be read for \"-p\": geteuid()=%d but you should be root.)\n"),
                  geteuid());
    } else {
        HIP_ERROR(_("(Not all processes could be identified, non-owned process info\n"
                    " will not be shown, you would have to be root to see it all.)\n"));
    }
}

/* These enums are used by IPX too. :-( */
enum {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING                 /* now a valid state */
};

#if HAVE_AFINET || HAVE_AFINET6

static const char *tcp_state[] = {
    "",
    N_("ESTABLISHED"),
    N_("SYN_SENT"),
    N_("SYN_RECV"),
    N_("FIN_WAIT1"),
    N_("FIN_WAIT2"),
    N_("TIME_WAIT"),
    N_("CLOSE"),
    N_("CLOSE_WAIT"),
    N_("LAST_ACK"),
    N_("LISTEN"),
    N_("CLOSING")
};

#endif

static void finish_this_one(int uid, unsigned long inode, UNUSED const char *timers)
{
    struct passwd *pw;
    char           temp[20];
    char          *ch;

    if (flag_exp > 1) {
        if (!(flag_not & FLAG_NUM_USER) && ((pw = getpwuid(uid)) != NULL)) {
            HIP_DEBUG("pw->pw_name: %-10s \n", pw->pw_name);
        } else {
            sys_ctx->uid = (unsigned int) uid;
        }
        sys_ctx->inode = inode;
    }

    if (flag_prg) {
        sprintf(temp, "%-16s", prg_cache_get(inode));
        if (strlen(temp) > 0) {
            ch           = strtok(temp, "/");
            sys_ctx->pid = strtol(ch, NULL, 10);
            ch           = strtok(NULL, " ");
            strcpy(sys_ctx->progname, ch);
        }
    }
    if (flag_opt) {
        HIP_DEBUG("timers %s\n", timers);
    }
//    putchar('\n');
    HIP_DEBUG("\n");
}

static void tcp_do_one(int lnr, const char *line, int src_port, int dst_port)
{
    unsigned long       rxq, txq, time_len, retr, inode;
    int                 num, local_port, rem_port, d, state, uid, timer_run, timeout;
    char                rem_addr[128], local_addr[128], timers[64], buffer[1024], more[512];
    char               *protname;
    char                tcp[]  = { 't', 'c', 'p', '\0' };
    char                tcp6[] = { 't', 'c', 'p', '6', '\0' };
    struct aftype      *ap;
    struct in6_addr_own in6_own;

#if HAVE_AFINET6
    struct sockaddr_in6  localaddr, remaddr;
    char                 addr6[INET6_ADDRSTRLEN];
    struct in6_addr      in6;
    extern struct aftype inet6_aftype;
#else
    struct sockaddr_in localaddr, remaddr;
#endif

    if (lnr == 0) {
        return;
    }

    num = sscanf(line,
                 "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %512s\n",
                 &d, local_addr, &local_port, rem_addr, &rem_port, &state,
                 &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode, more);

    if (strlen(local_addr) > 8) {
#if HAVE_AFINET6
        protname = tcp6;
        /* Demangle what the kernel gives us */
        sscanf(local_addr, "%08X%08X%08X%08X",
               &in6_own.u6_addr32[0], &in6_own.u6_addr32[1],
               &in6_own.u6_addr32[2], &in6_own.u6_addr32[3]);
        memcpy(&in6, &in6_own, sizeof(in6));
        inet_ntop(AF_INET6, &in6, addr6, sizeof(addr6));
        inet6_aftype.input(1, addr6, (struct sockaddr *) &localaddr);
        sscanf(rem_addr, "%08X%08X%08X%08X",
               &in6_own.u6_addr32[0], &in6_own.u6_addr32[1],
               &in6_own.u6_addr32[2], &in6_own.u6_addr32[3]);
        memcpy(&in6, &in6_own, sizeof(in6));
        inet_ntop(AF_INET6, &in6, addr6, sizeof(addr6));
        inet6_aftype.input(1, addr6, (struct sockaddr *) &remaddr);
        localaddr.sin6_family = AF_INET6;
        remaddr.sin6_family   = AF_INET6;
#endif
    } else {
        protname = tcp;
        sscanf(local_addr, "%X",
               &((struct sockaddr_in *) &localaddr)->sin_addr.s_addr);
        sscanf(rem_addr, "%X",
               &((struct sockaddr_in *) &remaddr)->sin_addr.s_addr);
        ((struct sockaddr *) &localaddr)->sa_family = AF_INET;
        ((struct sockaddr *) &remaddr)->sa_family   = AF_INET;
    }
    if (num < 11) {
        HIP_ERROR(_("warning, got bogus tcp line.\n"));
        return;
    }
    if ((ap = get_afntype(((struct sockaddr *) &localaddr)->sa_family)) == NULL) {
        HIP_ERROR(_("netstat: unsupported address family %d !\n"),
                  ((struct sockaddr *) &localaddr)->sa_family);
        return;
    }
    if (state == TCP_LISTEN) {
        time_len = 0;
        retr     = 0L;
        rxq      = 0L;
        txq      = 0L;
    }
    safe_strncpy(local_addr, ap->sprint((struct sockaddr *) &localaddr,
                                        flag_not), sizeof(local_addr));
    safe_strncpy(rem_addr, ap->sprint((struct sockaddr *) &remaddr, flag_not),
                 sizeof(rem_addr));
    if (flag_all || (flag_lst && !rem_port) || (!flag_lst && rem_port)) {
        snprintf(buffer, sizeof(buffer), "%s",
                 get_sname(htons(local_port), tcp, flag_not & FLAG_NUM_PORT));

        if (!flag_wide) {
            if ((strlen(local_addr) + strlen(buffer)) > 22) {
                local_addr[22 - strlen(buffer)] = '\0';
            }
        }

        strcat(local_addr, ":");
        strcat(local_addr, buffer);
        snprintf(buffer, sizeof(buffer), "%s",
                 get_sname(htons(rem_port), tcp, flag_not & FLAG_NUM_PORT));

        if (!flag_wide) {
            if ((strlen(rem_addr) + strlen(buffer)) > 22) {
                rem_addr[22 - strlen(buffer)] = '\0';
            }
        }

        strcat(rem_addr, ":");
        strcat(rem_addr, buffer);

//	int src_port = 57410; int dst_port = 2049;
        if (!flag_lst && ((local_port != src_port) || (rem_port != dst_port))) {
            HIP_DEBUG("local_port = %u and rem_port = %u \n", local_port, rem_port);
            return;
        } else if (flag_lst && (local_port != dst_port)) {
            return;
        }

        timers[0] = '\0';

        if (flag_opt) {
            switch (timer_run) {
            case 0:
                snprintf(timers, sizeof(timers), _("off (0.00/%ld/%d)"), retr, timeout);
                break;

            case 1:
                snprintf(timers, sizeof(timers), _("on (%2.2f/%ld/%d)"),
                         (double) time_len / HZ, retr, timeout);
                break;

            case 2:
                snprintf(timers, sizeof(timers), _("keepalive (%2.2f/%ld/%d)"),
                         (double) time_len / HZ, retr, timeout);
                break;

            case 3:
                snprintf(timers, sizeof(timers), _("timewait (%2.2f/%ld/%d)"),
                         (double) time_len / HZ, retr, timeout);
                break;

            default:
                snprintf(timers, sizeof(timers), _("unkn-%d (%2.2f/%ld/%d)"),
                         timer_run, (double) time_len / HZ, retr, timeout);
                break;
            }
        }
        HIP_DEBUG("%-4s  %6ld %6ld %-*s %-*s %-11s\n",
                  protname, rxq, txq, (int) netmax(23, strlen(local_addr)), local_addr, (int) netmax(23, strlen(rem_addr)), rem_addr, _(tcp_state[state]));

        strncpy(sys_ctx->proto, protname, strlen(protname));
        sprintf(sys_ctx->recv_q, "%6ld", rxq);
        sprintf(sys_ctx->send_q, "%6ld", txq);
        strncpy(sys_ctx->local_addr, local_addr, strlen(local_addr));
        strncpy(sys_ctx->remote_addr, rem_addr, strlen(rem_addr));
        sprintf(sys_ctx->state, "%-11s", _(tcp_state[state]));

        finish_this_one(uid, inode, timers);
    }
}

static int tcp_info(int src_port, int dst_port)
{
    INFO_GUTS6(_PATH_PROCNET_TCP, _PATH_PROCNET_TCP6, "AF INET (tcp)", src_port, dst_port, tcp_do_one);
}

/*
 * netstat_info_tpneW: Same effect as calling netstat -tpneWl | grep :src_port | grep :dst_port
 * @param src_port
 * @param dst_port
 * @param listening: Flag to tell netstat to lookup only listening port
 * @return int
 */
int netstat_info_tpneW(int src_port, int dst_port, struct system_app_context *ctx, uint8_t listening)
{
    int i;
    sys_ctx = ctx;

    flag_tcp++;
    flag_prg++, flag_exp++;
    flag_wide++;
    flag_not |= FLAG_NUM;

    if ((flag_inet || flag_inet6 || flag_sta) && !(flag_tcp || flag_udp || flag_raw)) {
        flag_tcp = flag_udp = flag_raw = 1;
    }

    if ((flag_tcp || flag_udp || flag_raw || flag_igmp) && !(flag_inet || flag_inet6)) {
        flag_inet = flag_inet6 = 1;
    }

    if (listening) {
        HIP_DEBUG("Netstat Lookup for only listening ports\n");
        flag_lst++;
    }

    flag_arg = flag_tcp + flag_udp + flag_raw + flag_unx + flag_ipx
               + flag_ax25 + flag_netrom + flag_igmp + flag_x25;


    for (;; ) {
        if (!flag_arg || flag_tcp || flag_udp || flag_raw) {
#if HAVE_AFINET
            prg_cache_load();
#else

#endif
        }

#if HAVE_AFINET
        if (!flag_arg || flag_tcp) {
            i = tcp_info(src_port, dst_port);
            if (i) {
                return i;
            }
        }
#endif

        if (!flag_cnt || i) {
            break;
        }
    }
    prg_cache_clear();
    return i;
}
