/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @brief An assortment of access for functions for hipd
 *
 * @author Miika Komu <miika@iki.fi>
 * @todo move the functions elsewhere and delete this file?
 */

/* required for s6_addr32 */
#define _BSD_SOURCE

#include "config.h"
#include "accessor.h"
#include "hipd.h"

unsigned int hipd_state         = HIPD_STATE_CLOSED;
#ifdef CONFIG_HIP_OPPORTUNISTIC
unsigned int opportunistic_mode = 1;
extern int hip_use_opptcp;
#endif // CONFIG_HIP_OPPORTUNISTIC
extern int hip_use_hi3;

/**
 * Set global daemon state.
 * @param state @see daemon_states
 */
void hipd_set_state(unsigned int state)
{
    hipd_state = (state & HIPD_STATE_MASK) | (hipd_state & ~HIPD_STATE_MASK);
}

/**
 * Get global daemon flag status.
 * @param state @see daemon_states
 * @return 1 if flag is on, 0 if not.
 */
int hipd_get_flag(unsigned int flag)
{
    return (hipd_state & flag) ? 1 : 0;
}

/**
 * Set global daemon flag.
 * @param state @see daemon_states
 */
void hipd_set_flag(unsigned int flag)
{
    hipd_state = hipd_state | flag;
}

/**
 * Get global daemon state.
 * @return @see daemon_states
 */
unsigned int hipd_get_state(void)
{
    return hipd_state & HIPD_STATE_MASK;
}

/**
 * Determines whether agent is alive, or not.
 *
 * @return non-zero, if agent is alive.
 */
int hip_agent_is_alive(void)
{
#ifdef CONFIG_HIP_AGENT
    return hip_agent_status;
#else
    return 0;
#endif /* CONFIG_HIP_AGENT */
}

#ifdef CONFIG_HIP_OPPORTUNISTIC
/**
 * Set opportunistic TCP status on or off
 *
 * @param msg a message with message type as SO_HIP_SET_OPPTCP_ON
 *            or SO_HIP_SET_OPPTCP_OFF
 */
void hip_set_opportunistic_tcp_status(struct hip_common *msg)
{
    struct sockaddr_in6 sock_addr;
    int retry, type, n;

    type = hip_get_msg_type(msg);

    _HIP_DEBUG("type=%d\n", type);

    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin6_family = AF_INET6;
    sock_addr.sin6_port   = htons(HIP_FIREWALL_PORT);
    sock_addr.sin6_addr   = in6addr_loopback;

    for (retry = 0; retry < 3; retry++) {
        /* Switched from hip_sendto() to hip_sendto_user() due to
         * namespace collision. Both message.h and user.c had functions
         * hip_sendto(). Introducing a prototype hip_sendto() to user.h
         * led to compiler errors --> user.c hip_sendto() renamed to
         * hip_sendto_user().
         *
         * Lesson learned: use function prototypes unless functions are
         * ment only for local (inside the same file where defined) use.
         * -Lauri 11.07.2008 */
        n = hip_sendto_user(msg, (struct sockaddr *) &sock_addr);
        if (n <= 0) {
            HIP_ERROR("hipconf opptcp failed (round %d)\n", retry);
            HIP_DEBUG("Sleeping few seconds to wait for fw\n");
            sleep(2);
        } else {
            HIP_DEBUG("hipconf opptcp ok (sent %d bytes)\n", n);
            break;
        }
    }

    if (type == SO_HIP_SET_OPPTCP_ON) {
        hip_use_opptcp = 1;
    } else {
        hip_use_opptcp = 0;
    }

    HIP_DEBUG("Opportunistic tcp set %s\n",
              (hip_use_opptcp ? "on" : "off"));
}

/**
 * query status for the opportunistic TCP extensions
 *
 * @return 1 if it is enabled or 0 otherwise
 */
int hip_get_opportunistic_tcp_status(void)
{
    return hip_use_opptcp;
}

/**
 * Set opportunistic mode
 *
 * @param msg A message containing a HIP_PARAM_UINT parameter.
 *            Zero means turning off, one means "normal" (hipconf run opp)
 *            and two means advanced (system-based opportunistic mode).
 * @return zero on success and negative on error
 */
int hip_set_opportunistic_mode(struct hip_common *msg)
{
    int err            =  0;
    unsigned int *mode = NULL;

    mode = hip_get_param_contents(msg, HIP_PARAM_UINT);
    if (!mode) {
        err = -EINVAL;
        goto out_err;
    }

    HIP_DEBUG("mode=%d\n", *mode);

    if (*mode == 0 || *mode == 1 || *mode == 2) {
        opportunistic_mode = *mode;
    } else {
        HIP_ERROR("Invalid value for opportunistic mode\n");
        err = -EINVAL;
        goto out_err;
    }

    hip_msg_init(msg);
    HIP_IFE(hip_build_user_hdr(msg,
                               (opportunistic_mode == 2 ?
                                SO_HIP_SET_OPPTCP_ON :
                                SO_HIP_SET_OPPTCP_OFF),
                               0), -1);
    hip_set_opportunistic_tcp_status(msg);

out_err:
    return err;
}

/**
 * Query opportunistic mode status
 *
 * @param msg an output parameter into which the function writes
 *            the status of the opportunistic mode
 * @return zero on success or negative on error
 */
int hip_query_opportunistic_mode(struct hip_common *msg)
{
    int err               = 0;
    unsigned int opp_mode = opportunistic_mode;

    hip_msg_init(msg);

    HIP_IFEL(hip_build_user_hdr(msg,
                                SO_HIP_ANSWER_OPPORTUNISTIC_MODE_QUERY, 0),
             -1, "build user header failed\n");

    HIP_IFEL(hip_build_param_contents(msg, (void *) &opp_mode,
                                      HIP_PARAM_UINT,
                                      sizeof(unsigned int)), -1,
             "build param opp_mode failed\n");

out_err:
    return err;
}
#endif /* CONFIG_HIP_OPPORTUNISTIC */

#ifdef CONFIG_HIP_I3
/**
 * turn hi3 support on or off
 *
 * @param msg a message with type SO_HIP_SET_HI3_ON or SO_HIP_SET_HI3_OFF
 */
void hip_set_hi3_status(struct hip_common *msg)
{
    struct sockaddr_in6 sock_addr;
    int retry, type, n;

    type = hip_get_msg_type(msg);

    _HIP_DEBUG("type=%d\n", type);

    bzero(&sock_addr, sizeof(sock_addr));
    sock_addr.sin6_family = AF_INET6;
    sock_addr.sin6_port   = htons(HIP_FIREWALL_PORT);
    sock_addr.sin6_addr   = in6addr_loopback;

    for (retry = 0; retry < 3; retry++) {
        n = hip_sendto_user(msg, (struct sockaddr *) &sock_addr);
        if (n <= 0) {
            HIP_ERROR("hipconf hi3 failed (round %d)\n", retry);
            HIP_DEBUG("Sleeping few seconds to wait for fw\n");
            sleep(2);
        } else {
            HIP_DEBUG("hipconf hi3 ok (sent %d bytes)\n", n);
            break;
        }
    }

    if (type == SO_HIP_SET_HI3_ON) {
        hip_i3_init();
        hip_use_hi3        = 1;
        hip_locator_status = SO_HIP_SET_LOCATOR_ON;
    } else {
        hip_locator_status = SO_HIP_SET_LOCATOR_OFF;
        hip_hi3_clean();
        hip_use_hi3        = 0;
    }

    HIP_DEBUG("hi3 set %s\n",
              (hip_use_hi3 ? "on" : "off"));
}

/**
 * query if Hi3 is enabled or not
 *
 * @return 1 if it is enabled or 0 otherwise
 */
int hip_get_hi3_status(void)
{
    return hip_use_hi3;
}
#endif /* CONFIG_HIP_I3 */

/**
 * Query if a pseudo HIT is stored in the host association
 * data base.
 *
 * @param msg a message containing a HIP_PARAM_PSEUDO_HIT parameter
 * @return zero on success or negative on error
 */
int hip_query_ip_hit_mapping(struct hip_common *msg)
{
    int err              = 0;
    unsigned int mapping = 0;
    struct in6_addr *hit = NULL;
    hip_ha_t *entry      = NULL;


    hit = (struct in6_addr *) hip_get_param_contents(msg, HIP_PARAM_PSEUDO_HIT);
    HIP_ASSERT(hit_is_opportunistic_hit(hit));

    entry = hip_hadb_try_to_find_by_peer_hit(hit);
    if (entry) {
        mapping = 1;
    } else {
        mapping = 0;
    }

    hip_msg_init(msg);

    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_ANSWER_IP_HIT_MAPPING_QUERY, 0),
             -1,
             "build user header failed\n");
    HIP_IFEL(hip_build_param_contents(msg,
                                      (void *) &mapping,
                                      HIP_PARAM_UINT,
                                      sizeof(unsigned int)),
              -1,
              "build param mapping failed\n");

out_err:
    return err;
}

/**
 * Query status of client-side HIP proxy
 *
 * @return one if the proxy mode is on or zero otherwise
 */
int hip_get_hip_proxy_status(void)
{
    return hipproxy;
}

/**
 * Set the client-side proxy on
 *
 * @return zero on success or negative on error
 */
int hip_set_hip_proxy_on(void)
{
    int err = 0;
    hipproxy = 1;
    HIP_DEBUG("hip_set_hip_proxy_on() invoked.\n");
    return err;
}

/**
 * Set the client-side proxy off
 *
 * @return zero on success or negative on error
 */
int hip_set_hip_proxy_off(void)
{
    int err = 0;
    hipproxy = 0;
    HIP_DEBUG("hip_set_hip_proxy_off() invoked.\n");
    return err;
}
