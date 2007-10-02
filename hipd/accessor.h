#ifndef _HIPD_ACCESSOR
#define _HIPD_ACCESSOR

#include "hipd.h"


/** @addtogroup daemon_states
 * @{
 */

/** Low mask for daemon states. */
#define HIPD_STATE_MASK		0xff
/** Daemon is ok and executing. */
#define HIPD_STATE_EXEC		0x00
/** Daemon is closing. */
#define HIPD_STATE_CLOSING	0x01
/** Daemon is closed, exiting main(). */
#define HIPD_STATE_CLOSED	0x02

/** High mask for daemon states. */
#define HIPD_FLAG_MASK		0xffffff00
/** Daemon is restarting. */
#define HIPD_FLAG_RESTART	0x00000100


/* @}  */


unsigned int hipd_get_state(void);
void hipd_set_state(unsigned int);
int hipd_get_flag(unsigned int);
void hipd_set_flag(unsigned int);
void hipd_clear_flag(unsigned int);

int hip_agent_is_alive();
int hip_set_opportunistic_mode(const struct hip_common *msg);
int hip_get_peer_hit(struct hip_common *msg, const struct sockaddr_un *src);
int hip_get_pseudo_hit(struct hip_common *msg);
int hip_query_opportunistic_mode(struct hip_common *msg);
int hip_query_ip_hit_mapping(struct hip_common *msg);


#endif /* _HIPD_ACCESSOR */

