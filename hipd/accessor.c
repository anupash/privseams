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

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "accessor.h"


unsigned int hipd_state         = HIPD_STATE_CLOSED;
#ifdef CONFIG_HIP_OPPORTUNISTIC
unsigned int opportunistic_mode = 1;
#endif // CONFIG_HIP_OPPORTUNISTIC


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

#ifdef CONFIG_HIP_OPPORTUNISTIC
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

#endif // CONFIG_HIP_OPPORTUNISTIC
