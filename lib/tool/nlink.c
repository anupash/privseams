/**
 * @file
 *
 * This code originates from <a
 * href="http://www.linuxfoundation.org/collaborate/workgroups/networking/iproute2">iproute2
 * tool</a> and libnetlink. The licence is
 * GNU/GPLv2. It was imported to HIPL because iproute2 has not been
 * librarized.
 *
 * This code implements <a
 * href="http://www.ietf.org/rfc/rfc3549.txt">NETLINK</a> interface with the kernel.
 * It is used for:
 * - adding and deletion of IPsec security policies and associations
 * - kernel tells hipd when to trigger (acquire) a base exchange
 * - deleting, adding and querying of routes
 * - adding or deleting addresses from network interfaces
 *
 * See iproute2 and libnetlink documentation on more information. It
 * should be noticed that the original code has been adapted for HIPL
 * to better suit the debugging macros and requirements for a
 * single-threaded HIP daemon.
 *
 * @brief NETLINK interface to the IPsec and routing modules in the kernel
 *
 * @author iproute2 authors
 *
 * @todo change this file into a command line interface to "ip" or "pfkey"
 */

#define _BSD_SOURCE

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "lib/core/debug.h"
#include "lib/core/hip_udp.h"
#include "lib/core/ife.h"
#include "lib/core/prefix.h"
#include "nlink.h"

#define HIP_MAX_NETLINK_PACKET 65537

#define PREFIXLEN_SPECIFIED 1

#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *) (((uint8_t *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

typedef int (*rtnl_filter)(const struct sockaddr_nl *,
                           const struct nlmsghdr *n, void **);

struct inet_prefix {
    uint8_t  family;
    uint8_t  bytelen;
    uint16_t bitlen;
    uint32_t flags;
    uint32_t data[4];
};

int lsi_total = 0;

/**
 * append a parameter to a netlink message
 *
 * @param n the message into which append a parameter
 * @param maxlen size of the data (including padding)
 * @param type type of the parameter
 * @param data the parameter to append
 * @param alen the length of the message
 * @return zero
 */
int addattr_l(struct nlmsghdr *n, unsigned maxlen, int type, const void *data,
              int alen)
{
    int            len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
        HIP_ERROR("addattr_l ERROR: message exceeded bound of %d\n", maxlen);
        return -1;
    }
    rta           = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len  = len;
    memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    return 0;
}

/**
 * Retrieve a NETLINK message from a netlink-based file handle
 *
 * @param nl a netlink file handle
 * @param handler a function pointer to the function that handles the message
 *        parameter each by each
 * @param arg an extra value to be passed for the handler function
 * @return always zero
 * @note Unfortunately libnetlink does not provide a generic receive a
 * message function. This is a modified version of the rtnl_listen
 * function that processes only a finite amount of messages and then
 * returns.
 */
int hip_netlink_receive(struct rtnl_handle *nl,
                        hip_filter handler,
                        void *arg)
{
    struct nlmsghdr   *h;
    struct sockaddr_nl nladdr = { 0 };
    struct iovec       iov;
    struct msghdr      msg = {
        (void *) &nladdr, sizeof(nladdr),
        &iov,             1,
        NULL,             0,
        0
    };
    unsigned           msg_len = 0;
    int                status  = 0;
    char               buf[NLMSG_SPACE(HIP_MAX_NETLINK_PACKET)];

    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid    = 0;
    nladdr.nl_groups = 0;
    iov.iov_base     = buf;
    iov.iov_len      = sizeof(buf);

    msg_len = recvfrom(nl->fd, buf, sizeof(struct nlmsghdr),
                       MSG_PEEK | MSG_DONTWAIT, NULL, NULL);
    if (msg_len != sizeof(struct nlmsghdr)) {
        HIP_ERROR("Bad netlink msg\n");
        return -1;
    }

    HIP_DEBUG("Received a netlink message\n");

    while (1) {
        iov.iov_len = sizeof(buf);

        /* Transitioned from recvmsg() to recvfrom() due to
         * "Netlink overrun" errors when executing
         * "hipconf rst all" */

        status = recvfrom(nl->fd, buf, sizeof(buf),
                          0, NULL, NULL);

        if (status < 0) {
            HIP_PERROR("perror: ");
            if (errno == EINTR) {
                continue;
            }
            HIP_ERROR("Netlink overrun.\n");
            return -1;
            continue;
        }
        if (status == 0) {
            HIP_ERROR("EOF on netlink\n");
            return -1;
        }
        if (msg.msg_namelen != sizeof(nladdr)) {
            HIP_ERROR("Sender address length == %d\n", msg.msg_namelen);
            return -1;
        }
        for (h = (struct nlmsghdr *) buf; status >= (int) sizeof(*h); ) {
            int err;
            int len = h->nlmsg_len;
            int l   = len - sizeof(*h);

            if (l < 0 || len > status) {
                if (msg.msg_flags & MSG_TRUNC) {
                    HIP_ERROR("Truncated netlink message\n");
                    return -1;
                }

                HIP_ERROR("Malformed netlink message: len=%d\n", len);
                return -1;
            }

            err = handler(h, len, arg);
            if (err < 0) {
                return err;
            }

            status -= NLMSG_ALIGN(len);
            h       = (struct nlmsghdr *) ((char *) h + NLMSG_ALIGN(len));
        }
        if (msg.msg_flags & MSG_TRUNC) {
            HIP_ERROR("Message truncated\n");
            break;
        }

        if (status) {
            HIP_ERROR("Remnant of size %d\n", status);
            return -1;
        }

        /* All messages processed */
        return 0;
    }
    return 0;
}

/**
 * Send a NETLINK message to the kernel
 *
 * @param nl netlink socket handle structure
 * @param n the netlink message to send
 * @param peer the process id of the recipient (zero for kernel)
 * @param groups group identifier
 * @param answer reply message from recipient
 * @param junk a function that filters unwanted messages
 * @param arg an extra argument for the junk filter
 * @return zero on success and negative on error
 * @note This is a copy from the libnetlink's talk function. It has a fixed
 * handling of message source/destination validation and proper buffer
 * handling for junk messages.
 */
int netlink_talk(struct rtnl_handle *nl, struct nlmsghdr *n, pid_t peer,
                 unsigned groups, struct nlmsghdr *answer,
                 hip_filter junk, void *arg)
{
    int                status, err = 0;
    unsigned           seq;
    struct nlmsghdr   *h;
    struct sockaddr_nl nladdr     = { 0 };
    char               buf[16384] = { 0 };
    struct iovec       iov        = {
        .iov_base = (void *) n,
        .iov_len  = n->nlmsg_len
    };
    struct msghdr      msg = {
        .msg_name    = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov     = &iov,
        .msg_iovlen  = 1,
    };

    /*Assign values to the socket address*/
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid    = peer;
    nladdr.nl_groups = groups;

    n->nlmsg_seq = seq = ++nl->seq;

    /* Note: the TALK_ACK are here because I experienced problems
     * with SMP machines. The application added a mapping which caused
     * the control flow to arrive here. The sendmsg adds an SP and the
     * while loop tries to read the ACK for the SP. However, there will
     * be an acquire message arriving from the kernel before we read the
     * ack which confuses the loop completely, so I disabled the ACK.
     * The reason why this all happens is that we are using the same
     * netlink socket to read both acquire messages and sending SP.
     * Only a single netlink socket exist per PID, so we either do it
     * as it is here or create another thread for handling acquires.
     * For testing SP/SA related issues you might want to re-enable these
     * -mk */
    if (HIP_NETLINK_TALK_ACK) {
        if (answer == NULL) {
            n->nlmsg_flags |= NLM_F_ACK;
        }
    }

    status = sendmsg(nl->fd, &msg, 0);

    if (status < 0) {
        HIP_PERROR("Cannot talk to rtnetlink");
        err = -1;
        goto out_err;
    }

    iov.iov_base = buf;

    while (HIP_NETLINK_TALK_ACK) {
        HIP_DEBUG("inside the while\n");
        iov.iov_len = sizeof(buf);
        status      = recvmsg(nl->fd, &msg, 0);

        if (status < 0) {
            if (errno == EINTR) {
                HIP_DEBUG("EINTR\n");
                continue;
            }
            HIP_PERROR("OVERRUN");
            continue;
        }
        if (status == 0) {
            HIP_ERROR("EOF on netlink.\n");
            err = -1;
            goto out_err;
        }
        if (msg.msg_namelen != sizeof(nladdr)) {
            HIP_ERROR("sender address length == %d\n",
                      msg.msg_namelen);
            err = -1;
            goto out_err;
        }
        for (h = (struct nlmsghdr *) buf; status >= (int) sizeof(*h); ) {
            int len = h->nlmsg_len;
            int l   = len - sizeof(*h);

            if (l < 0 || len > status) {
                if (msg.msg_flags & MSG_TRUNC) {
                    HIP_ERROR("Truncated message\n");
                    err = -1;
                    goto out_err;
                }
                HIP_ERROR("Malformed message: len=%d\n", len);
                err = -1;
                goto out_err;
            }

            if (nladdr.nl_pid != (unsigned) peer || h->nlmsg_seq != seq) {
                HIP_DEBUG("%d %d %d %d\n", nladdr.nl_pid,
                          peer, h->nlmsg_seq, seq);
                if (junk) {
                    err = junk(h, len, arg);
                    if (err < 0) {
                        err = -1;
                        goto out_err;
                    }
                }
                /* Don't forget to skip that message. */
                status -= NLMSG_ALIGN(len);
                h       = (struct nlmsghdr *) ((char *) h + NLMSG_ALIGN(len));
                continue;
            }

            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *nl_err = (struct nlmsgerr *) NLMSG_DATA(h);
                if (l < (int) sizeof(struct nlmsgerr)) {
                    HIP_ERROR("Truncated\n");
                } else {
                    errno = -nl_err->error;
                    if (errno == 0) {
                        if (answer) {
                            memcpy(answer, h, h->nlmsg_len);
                        }
                        goto out_err;
                    }
                    HIP_PERROR("NETLINK answers");
                }
                err = -1;
                goto out_err;
            }
            if (answer) {
                memcpy(answer, h, h->nlmsg_len);
                goto out_err;
            }

            HIP_ERROR("Unexpected netlink reply!\n");

            status -= NLMSG_ALIGN(len);
            h       = (struct nlmsghdr *) ((char *) h + NLMSG_ALIGN(len));
        }
        if (msg.msg_flags & MSG_TRUNC) {
            HIP_ERROR("Message truncated\n");
            continue;
        }
        if (status) {
            HIP_ERROR("Remnant of size %d\n", status);
            err = -1;
            goto out_err;
        }
    }

out_err:

    return err;
}

/**
 * open a netlink socket
 *
 * @param rth a structure containing netlink socket
 * @param subscriptions what messages to subscribe to
 * @param protocol the procotol for the socket (NETLINK_ROUTE)
 * return zero on success, non-zero on error
 *
 */
int rtnl_open_byproto(struct rtnl_handle *rth, unsigned subscriptions,
                      int protocol)
{
    socklen_t addr_len;
    int       sndbuf = 32768, rcvbuf = 32768;

    memset(rth, 0, sizeof(*rth));

    rth->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
    if (rth->fd < 0) {
        HIP_PERROR("Cannot open a netlink socket");
        return -1;
    }
    if (setsockopt(rth->fd, SOL_SOCKET, SO_SNDBUF,
                   &sndbuf, sizeof(sndbuf)) < 0) {
        HIP_PERROR("SO_SNDBUF");
        return -1;
    }
    if (setsockopt(rth->fd, SOL_SOCKET, SO_RCVBUF,
                   &rcvbuf, sizeof(rcvbuf)) < 0) {
        HIP_PERROR("SO_RCVBUF");
        return -1;
    }

    memset(&rth->local, 0, sizeof(rth->local));
    rth->local.nl_family = AF_NETLINK;
    rth->local.nl_groups = subscriptions;

    if (bind(rth->fd, (struct sockaddr *) &rth->local,
             sizeof(rth->local)) < 0) {
        HIP_PERROR("Cannot bind a netlink socket");
        return -1;
    }
    addr_len = sizeof(rth->local);
    if (getsockname(rth->fd, (struct sockaddr *) &rth->local,
                    &addr_len) < 0) {
        HIP_PERROR("Cannot getsockname");
        return -1;
    }
    if (addr_len != sizeof(rth->local)) {
        HIP_ERROR("Wrong address length %d\n", addr_len);
        return -1;
    }
    if (rth->local.nl_family != AF_NETLINK) {
        HIP_ERROR("Wrong address family %d\n", rth->local.nl_family);
        return -1;
    }
    rth->seq = time(NULL);
    return 0;
}

/**
 * close a netlink socket
 *
 * @param rth a structure containing a netlink socket
 */
void rtnl_close(struct rtnl_handle *rth)
{
    close(rth->fd);
}

/**
 * map a network device to its numerical index
 *
 * @param name the device name to be matched from idxmap
 * @param idxmap an idxmap structure containing information on all devices
 * @return the device index
 */
static unsigned ll_name_to_index(const char *name, struct idxmap **idxmap)
{
    static char    ncache[16];
    static int     icache;
    struct idxmap *im;
    int            i;

    if (name == NULL) {
        return 0;
    }
    if (icache && strcmp(name, ncache) == 0) {
        return icache;
    }
    for (i = 0; i < 16; i++) {
        for (im = idxmap[i]; im; im = im->next) {
            if (strcmp(im->name, name) == 0) {
                icache = im->index;
                strcpy(ncache, name);
                return im->index;
            }
        }
    }

    /** @todo having more that one NETLINK socket open at the same
     *  time is bad! See hipd.c comments on addresses variable */
    return if_nametoindex(name);
}

/**
 * a NULL checking wrapper for strtoul (convert a string to an unsigned long int)
 *
 * @param val the result of the conversion
 * @param arg a number as a character array
 * @param base the base for conversion, see man strtoul
 * @return zero on success and negative on error
 */
static int get_unsigned(unsigned *val, const char *arg, int base)
{
    unsigned long res;
    char         *ptr;

    if (!arg || !*arg) {
        return -1;
    }
    res = strtoul(arg, &ptr, base);
    if (!ptr || ptr == arg || *ptr || res > UINT_MAX) {
        return -1;
    }
    *val = res;
    return 0;
}

/**
 * construct an inet_prefix structure (excluding prefix) based the given string
 *
 * @param addr inet_prefix structure to be filled in (caller allocates)
 * @param name an address string to be converted to the addr argument
 * @param family address family of the name
 * @return zero success and negative on error
 */
static int get_addr_1(struct inet_prefix *addr, const char *name, int family)
{
    const char    *cp;
    unsigned char *ap = (unsigned char *) addr->data;
    int            i;

    memset(addr, 0, sizeof(*addr));

    if (strcmp(name, "default") == 0 ||
        strcmp(name, "all") == 0 ||
        strcmp(name, "any") == 0) {
        if (family == AF_DECnet) {
            return -1;
        }
        addr->family  = family;
        addr->bytelen = (family == AF_INET6 ? 16 : 4);
        addr->bitlen  = -1;
        return 0;
    }

    if (strchr(name, ':')) {
        addr->family = AF_INET6;
        if (family != AF_UNSPEC && family != AF_INET6) {
            return -1;
        }
        if (inet_pton(AF_INET6, name, addr->data) <= 0) {
            return -1;
        }
        addr->bytelen = 16;
        addr->bitlen  = -1;
        return 0;
    }

    addr->family = AF_INET;
    if (family != AF_UNSPEC && family != AF_INET) {
        return -1;
    }
    addr->bytelen = 4;
    addr->bitlen  = -1;
    for (cp = name, i = 0; *cp; cp++) {
        if (*cp <= '9' && *cp >= '0') {
            ap[i] = 10 * ap[i] + (*cp - '0');
            continue;
        }
        if (*cp == '.' && ++i <= 3) {
            continue;
        }
        return -1;
    }
    return 0;
}

/**
 * construct an inet_prefix structure (including prefix) based the given string
 *
 * @param dst inet_prefix structure to be filled in (caller allocates)
 * @param arg an address string to be converted to the addr argument
 * @param family address family of the name
 * @return zero success and negative on error
 */
static int get_prefix_1(struct inet_prefix *dst, char *arg, int family)
{
    int      err;
    unsigned plen;
    char    *slash;

    memset(dst, 0, sizeof(*dst));

    if (strcmp(arg, "default") == 0 ||
        strcmp(arg, "any") == 0 ||
        strcmp(arg, "all") == 0) {
        if (family == AF_DECnet) {
            return -1;
        }
        dst->family  = family;
        dst->bytelen = 0;
        dst->bitlen  = 0;
        return 0;
    }

    slash = strchr(arg, '/');
    if (slash) {
        *slash = 0;
    }

    err = get_addr_1(dst, arg, family);
    if (err == 0) {
        switch (dst->family) {
        case AF_INET6:
            dst->bitlen = 128;
            break;
        case AF_DECnet:
            dst->bitlen = 16;
            break;
        default:
        case AF_INET:
            dst->bitlen = 32;
        }
        if (slash) {
            if (get_unsigned(&plen, slash + 1, 0) || plen > dst->bitlen) {
                err = -1;
                goto done;
            }
            dst->flags |= PREFIXLEN_SPECIFIED;
            dst->bitlen = plen;
        }
    }
done:
    if (slash) {
        *slash = '/';
    }
    return err;
}

/**
 * append a 32-bit attribute into a netlink message
 *
 * @param n the netlink message
 * @param maxlen the length of the attribute with padding
 * @param type type of the attribute
 * @param data the attribute
 * @return zero on success and negative on error
 */
static int addattr32(struct nlmsghdr *n, unsigned maxlen, int type, uint32_t data)
{
    int            len = RTA_LENGTH(4);
    struct rtattr *rta;
    if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen) {
        HIP_ERROR("addattr32: Error! max allowed bound %d exceeded\n", maxlen);
        return -1;
    }
    rta           = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len  = len;
    memcpy(RTA_DATA(rta), &data, 4);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;
    return 0;
}

/**
 * request for information from the kernel
 *
 * @param rth rtnl_handle structure containing a pointer to netlink
 * @param family address family
 * @param type request type
 * @return On success, returns number of chars  sent to kernel. On
 *         error, returns -1 and sets errno.
 * @note the reply has to be read separately
 */
static int rtnl_wilddump_request(struct rtnl_handle *rth, int family, int type)
{
    struct {
        struct nlmsghdr nlh;
        struct rtgenmsg g;
    } req;
    struct sockaddr_nl nladdr = { 0 };

    nladdr.nl_family = AF_NETLINK;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len   = sizeof(req);
    req.nlh.nlmsg_type  = type;
    req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
    req.nlh.nlmsg_pid   = 0;
    req.nlh.nlmsg_seq   = rth->dump = ++rth->seq;
    req.g.rtgen_family  = family;

    return sendto(rth->fd, &req, sizeof(req), 0,
                  (struct sockaddr *) &nladdr, sizeof(nladdr));
}

/**
 * Retrieve a netlink message and apply optional junk filter
 *
 * @param rth rtnl_handle structure containing a netlink socket
 * @param filter an optional pointer to a filter function
 * @param arg1 optional argument for the filter function
 * @param junk an optional pointer to a junk handler function
 * @param arg2 optional argument for the junk function
 * @return zero on success and negative on error
 */
static int rtnl_dump_filter(struct rtnl_handle *rth,
                            rtnl_filter filter,
                            void *arg1,
                            rtnl_filter junk,
                            void *arg2)
{
    struct sockaddr_nl nladdr;
    struct iovec       iov;
    struct msghdr      msg = {
        .msg_name    = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov     = &iov,
        .msg_iovlen  = 1,
    };
    char               buf[16384];

    while (1) {
        int              status;
        struct nlmsghdr *h;

        iov.iov_base = buf;
        iov.iov_len  = sizeof(buf);
        status       = recvmsg(rth->fd, &msg, 0);

        if (status < 0) {
            if (errno == EINTR) {
                continue;
            }
            HIP_PERROR("OVERRUN");
            continue;
        }

        if (status == 0) {
            HIP_ERROR("EOF on netlink\n");
            return -1;
        }

        h = (struct nlmsghdr *) buf;
        while (NLMSG_OK(h, (unsigned) status)) {
            int err = 0;

            if (nladdr.nl_pid != 0 ||
                h->nlmsg_pid != rth->local.nl_pid ||
                h->nlmsg_seq != rth->dump) {
                if (junk) {
                    err = junk(&nladdr, h, arg2);
                    if (err < 0) {
                        return err;
                    }
                }
                goto skip_it;
            }

            if (h->nlmsg_type == NLMSG_DONE) {
                return 0;
            }
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *nlerr = (struct nlmsgerr *) NLMSG_DATA(h);
                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                    HIP_ERROR("ERROR truncated\n");
                } else {
                    errno = -nlerr->error;
                    HIP_PERROR("RTNETLINK answers");
                }
                return -1;
            }
            if (filter) {
                err = filter(&nladdr, h, arg1);
            }
            if (err < 0) {
                return err;
            }

skip_it:
            h = NLMSG_NEXT(h, status);
        }
        if (msg.msg_flags & MSG_TRUNC) {
            HIP_ERROR("Message truncated\n");
            continue;
        }
        if (status) {
            HIP_ERROR("Remnant of size %d\n", status);
            return -1;
        }
    }
}

/**
 * Fill in an idxmap structure (a list of network interfaces and related info)
 *
 * @param rth structure containing a netlink socket
 * @param idxmap idxmap structure to be filled
 * @return zero on success and negative on error
 */
static int ll_init_map(struct rtnl_handle *rth, struct idxmap **idxmap)
{
    if (rtnl_wilddump_request(rth, AF_UNSPEC, RTM_GETLINK) < 0) {
        HIP_PERROR("Cannot send dump request");
        return -1;
    }

    if (rtnl_dump_filter(rth, NULL, idxmap, NULL, NULL) < 0) {
        HIP_ERROR("Dump terminated\n");
        return -1;
    }
    return 0;
}

/**
 * Add, delete or modify a route in the kernel
 *
 * @param rth rtnl_handle structure containing a netlink socket
 * @param cmd add, delete or modify (RTM_*)
 * @param flags flags (NLM_F_*)
 * @param family address family for the new route
 * @param ip the address for which to modify the route
 * @param dev the network device of the ip
 * @return zero
 */
int hip_iproute_modify(struct rtnl_handle *rth,
                       int cmd, int flags, int family, char *ip,
                       const char *dev)
{
    struct {
        struct nlmsghdr n;
        struct rtmsg    r;
        char            buf[1024];
    } req1;
    struct inet_prefix dst;
    struct idxmap     *idxmap[16];
    int                dst_ok = 0, err = 0;
    int                idx, i;

    memset(&req1, 0, sizeof(req1));
    for (i = 0; i < 16; i++) {
        idxmap[i] = NULL;
    }

    req1.n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    req1.n.nlmsg_flags = NLM_F_REQUEST | flags;
    req1.n.nlmsg_type  = cmd;
    req1.r.rtm_family  = family;
    req1.r.rtm_table   = RT_TABLE_MAIN;
    req1.r.rtm_scope   = RT_SCOPE_NOWHERE;

    if (cmd != RTM_DELROUTE) {
        req1.r.rtm_protocol = RTPROT_BOOT;
        req1.r.rtm_scope    = RT_SCOPE_UNIVERSE;
        req1.r.rtm_type     = RTN_UNICAST;
    }

    if (family == AF_INET) {
        HIP_DEBUG("Setting %s as route for %s device with family %d\n",
                  ip, dev, family);
    }
    HIP_IFEL(get_prefix_1(&dst, ip, req1.r.rtm_family), -1, "prefix\n");
    req1.r.rtm_dst_len = dst.bitlen;
    dst_ok             = 1;
    if (dst.bytelen) {
        addattr_l(&req1.n, sizeof(req1), RTA_DST, &dst.data,
                  dst.bytelen);
    }

    ll_init_map(rth, idxmap);

    HIP_IFEL((idx = ll_name_to_index(dev, idxmap)) == 0, -1,
             "ll_name_to_index failed\n");

    addattr32(&req1.n, sizeof(req1), RTA_OIF, idx);

    HIP_IFEL(netlink_talk(rth, &req1.n, 0, 0, NULL, NULL, NULL) < 0, -1,
             "netlink_talk failed\n");

out_err:
    for (i = 0; i < 16; i++) {
        free(idxmap[i]);
    }

    return 0;
}

/**
 * Parse a rtattr structure into an array of pointers. The pointers
 * point to the attributes contained in the structure
 *
 * @param tb the resulting array of pointers (can contain NULL pointers)
 * @param max of tb array
 * @param rta the routing attribute structure to be parsed
 * @param len the length of the rta structure
 * @return zero
 */
static int parse_rtattr(struct rtattr *tb[],
                        int max,
                        struct rtattr *rta,
                        int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta;
        }
        rta = RTA_NEXT(rta, len);
    }

    if (len) {
        HIP_ERROR("Deficit len %d, rta_len=%d\n", len, rta->rta_len);
    }

    return 0;
}

/**
 * Parse source address from a netlink message
 *
 * @param n the netlink message
 * @param src_addr the source address of the netlink message to this output argument
 * @return zero
 */
static int hip_parse_src_addr(struct nlmsghdr *n, struct in6_addr *src_addr)
{
    struct rtmsg  *r = NLMSG_DATA(n);
    struct rtattr *tb[RTA_MAX + 1];
    union {
        struct in_addr  *in;
        struct in6_addr *in6;
    } addr;
    int entry;

    /* see print_route() in ip/iproute.c */
    parse_rtattr(tb, RTA_MAX, RTM_RTA(r), n->nlmsg_len);
    addr.in6 = (struct in6_addr *) RTA_DATA(tb[2]);
    entry    = 7;
    addr.in6 = (struct in6_addr *) RTA_DATA(tb[entry]);

    if (r->rtm_family == AF_INET) {
        IPV4_TO_IPV6_MAP(addr.in, src_addr);
    } else {
        memcpy(src_addr, addr.in6, sizeof(struct in6_addr));
    }

    return 0;
}

/**
 * A wrapper for get_prefix_1. Does the same thing but also checks
 * AF_PACKET.
 *
 * @param dst inet_prefix structure to be filled in (caller allocates)
 * @param arg an address string to be converted to the addr argument
 * @param family address family of the name
 * @return zero success and negative on error
 */
static int get_prefix(struct inet_prefix *dst, char *arg, int family)
{
    if (family == AF_PACKET) {
        HIP_ERROR("Error: \"%s\" may be inet prefix, but it is not allowed in this context.\n", arg);
        return -1;
    }
    if (get_prefix_1(dst, arg, family)) {
        HIP_ERROR("Error: an inet prefix is expected rather than \"%s\".\n",
                  arg);
        return -1;
    }
    return 0;
}

/**
 * Send a netlink message
 *
 * @param rtnl a rtnl_handle structure with a netlink socket
 * @param n the message to send to the kernel
 * @param peer process id of the recipient (zero for kernel)
 * @param groups group id of the recipient (zero for any)
 * @param answer If present, filled with the response from the recipient. Allocated
 *               by the caller. Set answer to NULL for no response.
 * @param junk junk handler function
 * @param jarg an optioanl extra argument to be passed to the junk handler
 * @return zero on success and negative on error
 */
static int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, pid_t peer,
                     unsigned groups, struct nlmsghdr *answer,
                     rtnl_filter junk,
                     void *jarg)
{
    int                status;
    unsigned           seq;
    struct nlmsghdr   *h;
    struct sockaddr_nl nladdr = { 0 };
    struct iovec       iov    = {
        .iov_base = (void *) n,
        .iov_len  = n->nlmsg_len
    };
    struct msghdr      msg = {
        .msg_name    = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov     = &iov,
        .msg_iovlen  = 1,
    };
    char               buf[16384] = { 0 };

    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid    = peer;
    nladdr.nl_groups = groups;

    n->nlmsg_seq = seq = ++rtnl->seq;

    if (answer == NULL) {
        n->nlmsg_flags |= NLM_F_ACK;
    }

    status = sendmsg(rtnl->fd, &msg, 0);
    if (status < 0) {
        HIP_PERROR("Cannot talk to rtnetlink");
        return -1;
    }

    iov.iov_base = buf;

    while (1) {
        iov.iov_len = sizeof(buf);
        status      = recvmsg(rtnl->fd, &msg, 0);

        if (status < 0) {
            if (errno == EINTR) {
                continue;
            }
            HIP_PERROR("OVERRUN");
            continue;
        }
        if (status == 0) {
            HIP_ERROR("EOF on netlink\n");
            return -1;
        }
        if (msg.msg_namelen != sizeof(nladdr)) {
            HIP_ERROR("sender address length == %d\n", msg.msg_namelen);
            return -1;
        }
        for (h = (struct nlmsghdr *) buf; status >= (int) sizeof(*h); ) {
            int err;
            int len = h->nlmsg_len;
            int l   = len - sizeof(*h);

            if (l < 0 || len > status) {
                if (msg.msg_flags & MSG_TRUNC) {
                    HIP_ERROR("Truncated message\n");
                    return -1;
                }
                HIP_ERROR("malformed message: len=%d\n", len);
                return -1;
            }

            if (nladdr.nl_pid != (unsigned) peer ||
                h->nlmsg_pid != rtnl->local.nl_pid ||
                h->nlmsg_seq != seq) {
                if (junk) {
                    err = junk(&nladdr, h, jarg);
                    if (err < 0) {
                        return err;
                    }
                }
                /* Don't forget to skip that message. */
                status -= NLMSG_ALIGN(len);
                h       = (struct nlmsghdr *) ((char *) h + NLMSG_ALIGN(len));

                continue;
            }

            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *nlerr = (struct nlmsgerr *) NLMSG_DATA(h);
                if (l < (int) sizeof(struct nlmsgerr)) {
                    HIP_ERROR("ERROR truncated\n");
                } else {
                    errno = -nlerr->error;
                    if (errno == 0) {
                        if (answer) {
                            memcpy(answer, h, h->nlmsg_len);
                        }
                        return 0;
                    }
                    HIP_PERROR("RTNETLINK answers");
                }
                return -1;
            }
            if (answer) {
                memcpy(answer, h, h->nlmsg_len);
                return 0;
            }

            HIP_ERROR("Unexpected reply!!!\n");

            status -= NLMSG_ALIGN(len);
            h       = (struct nlmsghdr *) ((char *) h + NLMSG_ALIGN(len));
        }
        if (msg.msg_flags & MSG_TRUNC) {
            HIP_ERROR("Message truncated\n");
            continue;
        }
        if (status) {
            HIP_ERROR("Remnant of size %d\n", status);
            return -1;
        }
    }
}

/**
 * Query a source address for the given destination address from the kernel
 *
 * @param rth rtnl_handle structure containing a netlink socket
 * @param src_addr queried source address (possibly in IPv6 mapped format if IPv4 address)
 * @param dst_addr the destination address
 * @param idev optional source network device
 * @param odev optional destination network device
 * @param family the family of the source and destination address
 * @param idxmap a prefilled array of pointers to network device information
 * @return zero on success and negative on failure
 */
int hip_iproute_get(struct rtnl_handle *rth, struct in6_addr *src_addr,
                    const struct in6_addr *dst_addr, char *idev, char *odev,
                    int family, struct idxmap **idxmap)
{
    struct {
        struct nlmsghdr n;
        struct rtmsg    r;
        char            buf[1024];
    } req;

    int                err = 0, idx, preferred_family = family;
    struct inet_prefix addr;
    char               dst_str[INET6_ADDRSTRLEN];
    struct in_addr     ip4;
    HIP_ASSERT(dst_addr);

    HIP_DEBUG_IN6ADDR("Getting route for destination address", dst_addr);

    if (IN6_IS_ADDR_V4MAPPED(dst_addr)) {
        IPV6_TO_IPV4_MAP(dst_addr, &ip4);
        preferred_family = AF_INET;
        HIP_IFEL(!inet_ntop(preferred_family, &ip4, dst_str, INET6_ADDRSTRLEN),
                 -1, "inet_pton\n");
    } else {
        HIP_IFEL(!inet_ntop(preferred_family, dst_addr, dst_str, INET6_ADDRSTRLEN),
                 -1, "inet_pton\n");
    }
    memset(&req, 0, sizeof(req));

    req.n.nlmsg_len    = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.n.nlmsg_flags  = NLM_F_REQUEST;
    req.n.nlmsg_type   = RTM_GETROUTE;
    req.r.rtm_family   = preferred_family;
    req.r.rtm_table    = 0;
    req.r.rtm_protocol = 0;
    req.r.rtm_scope    = 0;
    req.r.rtm_type     = 0;
    req.r.rtm_src_len  = 0;
    req.r.rtm_dst_len  = 0;
    req.r.rtm_tos      = 0;

    get_prefix(&addr, dst_str, req.r.rtm_family);

    if (addr.bytelen) {
        addattr_l(&req.n, sizeof(req), RTA_DST, &addr.data,
                  addr.bytelen);
    }
    req.r.rtm_dst_len = addr.bitlen;

    ll_init_map(rth, idxmap);

    if (idev) {
        HIP_IFEL((idx = ll_name_to_index(idev, idxmap)) == 0,
                 -1, "Cannot find device \"%s\"\n", idev);
        addattr32(&req.n, sizeof(req), RTA_IIF, idx);
    }
    if (odev) {
        HIP_IFEL((idx = ll_name_to_index(odev, idxmap)) == 0,
                 -1, "Cannot find device \"%s\"\n", odev);
        addattr32(&req.n, sizeof(req), RTA_OIF, idx);
    }
    HIP_IFE(rtnl_talk(rth, &req.n, 0, 0, &req.n, NULL, NULL) < 0, -1);
    HIP_IFE(hip_parse_src_addr(&req.n, src_addr), -1);

out_err:

    return err;
}

/**
 * convert a string with an IPv6-mapped IPv4 address with an optional prefix to
 * numberic presentation
 *
 * @param ip a string with an IPv6 address with an optional prefix
 * @param ip4 output argument: a numerical representation (struct in_addr) of the
 *        ip argument
 * @return zero on success and non-zero on failure
 */
static int convert_ipv6_slash_to_ipv4_slash(char *ip, struct in_addr *ip4)
{
    struct in6_addr ip6_aux;
    char           *slash     = strchr(ip, '/');
    char           *aux_slash = NULL;
    int             err       = 0;

    if (slash) {
        HIP_IFEL(!(aux_slash = malloc(sizeof(slash))), -1, "alloc\n");
        strcpy(aux_slash, slash);
        *slash = 0;
    }

    inet_pton(AF_INET6, ip, &ip6_aux);

    if ((err = IN6_IS_ADDR_V4MAPPED(&ip6_aux))) {
        IPV6_TO_IPV4_MAP(&ip6_aux, ip4);
    }
    *slash = *aux_slash;

out_err:
    free(aux_slash);
    return err;
}

/**
 * Add, delete or modify an address on a network interface
 *
 * @param rth rtnl_handle structure containing a netlink socket
 * @param cmd add, delete or modify
 * @param family the family of the address to be modified
 * @param ip the IP address (as a string) to be modified
 * @param dev the device of the IP address as a string
 * @param idxmap a prefilled array of pointers to network device information
 * @return zero on success and negative on failure
 */
int hip_ipaddr_modify(struct rtnl_handle *rth, int cmd, int family, char *ip,
                      const char *dev, struct idxmap **idxmap)
{
    struct {
        struct nlmsghdr  n;
        struct ifaddrmsg ifa;
        char             buf[256];
    } req;

    struct inet_prefix lcl;
    int                local_len = 0, err = 0, size_dev;
    struct in_addr     ip4       = { 0 };
    int                ip_is_v4  = 0;
    char               label[4];
    char              *res = NULL;
    int                aux;

    memset(&req, 0, sizeof(req));
    if (convert_ipv6_slash_to_ipv4_slash(ip, &ip4)) {
        family   = AF_INET;
        ip_is_v4 = 1;
        lsi_total++;
        ip = strcat(inet_ntoa(ip4), HIP_LSI_FULL_PREFIX_STR);
        sprintf(label, ":%d", lsi_total);
        HIP_DEBUG("Label %s:%d\n", ip, lsi_total);
    }

    req.n.nlmsg_len    = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.n.nlmsg_type   = cmd;
    req.n.nlmsg_flags  = NLM_F_REQUEST;
    req.ifa.ifa_family = family;

    get_prefix_1(&lcl, ip, req.ifa.ifa_family);
    addattr_l(&req.n, sizeof(req), IFA_LOCAL, &lcl.data, lcl.bytelen);

    if (ip_is_v4 && lsi_total > 0) {
        size_dev = sizeof(dev) + sizeof(label);
        res      = calloc(1, size_dev + 1);
        strcat(res, dev);
        strcat(res, label);
        addattr_l(&req.n, sizeof(req), IFA_LABEL, res,
                  strlen(dev) + strlen(label) + 1);
    }

    local_len = lcl.bytelen;

    if (req.ifa.ifa_prefixlen == 0) {
        req.ifa.ifa_prefixlen = lcl.bitlen;
    }

    HIP_IFEL((req.ifa.ifa_index = ll_name_to_index(dev, idxmap)) == 0,
             -1, "ll_name_to_index failed\n");

    HIP_DEBUG("IFA INDEX IS %d\n", req.ifa.ifa_index);

    // adds to the device dummy0
    aux = netlink_talk(rth, &req.n, 0, 0, NULL, NULL, NULL);
    HIP_DEBUG("value exit function netlink_talk %i\n", aux);
    HIP_IFEL(aux < 0, -1, "netlink talk failed\n");

out_err:
    free(res);
    return 0;
}

/**
 * Find a suitable socket type to set up a network device flags
 *
 * @return a positive file descriptor on success and negative on failure
 */
static int get_ctl_fd(void)
{
    int s_errno;
    int fd;

    fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        return fd;
    }
    s_errno = errno;
    fd      = socket(PF_PACKET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        return fd;
    }
    fd = socket(PF_INET6, SOCK_DGRAM, 0);
    if (fd >= 0) {
        return fd;
    }
    errno = s_errno;
    HIP_PERROR("Cannot create control socket");
    return -1;
}

/**
 * set flags for a (virtual) network interface
 *
 * @param dev the network interface name as a string
 * @param flags flags to set for the network interface
 * @param mask mask for the flags
 * @return zero on success and negative on error
 */
static int do_chflags(const char *dev, uint32_t flags, uint32_t mask)
{
    struct ifreq ifr;
    int          fd;
    int          err;

    strncpy(ifr.ifr_name, dev, IF_NAMESIZE);
    fd = get_ctl_fd();
    if (fd < 0) {
        return -1;
    }

    err = ioctl(fd, SIOCGIFFLAGS, &ifr);    // get interface dummy0 flags
    if (err) {
        HIP_PERROR("SIOCGIFFLAGS");
        close(fd);
        return -1;
    }

    if ((ifr.ifr_flags ^ flags) & mask) {
        ifr.ifr_flags &= ~mask;
        ifr.ifr_flags |= mask & flags;
        err            = ioctl(fd, SIOCSIFFLAGS, &ifr);
        if (err) {
            HIP_PERROR("SIOCSIFFLAGS");
        }
    }

    close(fd);
    return err;
}

/**
 * Switch a network interface up or down
 *
 * @param dev the name of the network interface as a string
 * @param up 1 when setting interface up and 0 for down
 * @return zero on success and negative on failure
 */
int set_up_device(const char *dev, int up)
{
    int      err   = -1, total_add;
    uint32_t mask  = 0;
    uint32_t flags = 0;
    char     label[4];
    char    *res = NULL;
    int      size_dev;

    if (up == 1) {
        mask  |= IFF_UP;
        flags |= IFF_UP;
    } else {
        mask  |= IFF_UP;
        flags &= ~IFF_UP;
        for (total_add = lsi_total; total_add > 0; total_add--) {
            sprintf(label, ":%d", total_add);
            size_dev = sizeof(dev) + sizeof(label);
            res      = calloc(1, size_dev + 1);
            strcat(strcat(res, dev), label);
            err = do_chflags(res, flags, mask);
            free(res);
        }
    }
    err = do_chflags(dev, flags, mask);

    return err;
}
