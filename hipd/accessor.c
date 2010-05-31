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

#define _BSD_SOURCE

#include "config.h"
#include "accessor.h"
#include "hipd.h"

unsigned int hipd_state         = HIPD_STATE_CLOSED;

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
 * @param flag @see daemon_states
 * @return 1 if flag is on, 0 if not.
 */
int hipd_get_flag(unsigned int flag)
{
    return (hipd_state & flag) ? 1 : 0;
}

/**
 * Set global daemon flag.
 * @param flag @see daemon_states
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
