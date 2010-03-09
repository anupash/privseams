#ifndef HIP_HIPD_HI3_H
#define HIP_HIPD_HI3_H

#include "config.h"
#include "user.h"
#include "hipd.h"
#include "lib/core/protodefs.h"
#include "i3/i3_client/i3_client_api.h"
#include "i3/i3/i3_id.h"

#define HIPL_HI3_FILE     HIPL_SYSCONFDIR "/hi3_conf"

#define HIPL_HI3_FILE_EX \
    "<?xml version=\"1.0\"?>\n\
                <I3ConfigFile version=\"0.1\">\n\
                <I3ServerDetails\n\
                UsePing=\"yes\"\n\
                UseTCP=\"yes\"\n\
                ServerListURL=\"rose.cs.berkeley.edu:8080/i3_status.txt\"\n\
                >\n\
             <!-- If UsePing is false, you have to make sure that\n\
             this first hop i3 server is running.  You can\n\
             check the status of the i3 servers at\n\
             http://i3.cs.berkeley.edu\n\
             -->\n\
\n\
            </I3ServerDetails>\n\
</I3ConfigFile>\n"

int hip_i3_init(void);
int hip_hi3_clean(void);

/**
 * Does some i3 related stuff to I2 packet.
 *
 * In an attempt to clean up the input.c code, this functionality was moved to
 * a function from hip_handle_i2(). What the code does, remains a mystery.
 * -Lauri 24.07.2008
 *
 * @param locator  a pointer to a locator parameter. This is both a source and a
 *                 destination buffer.
 * @param i2_info  a pointer to a data structure that has information if i3 is
 *                 in use or not.
 * @param i2_saddr a pointer to I2 packet source IP address. This is both a
 *                 source and a destination buffer.
 * @param i2_daddr a pointer to I2 packet destination IP address.
 */
int hip_do_i3_stuff_for_i2(struct hip_locator *locator, hip_portpair_t *i2_info,
                           in6_addr_t *i2_saddr, in6_addr_t *i2_daddr);

#endif /* HIP_HIPD_HI3_H */
