/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>
 *
 * Implementation of <a
 * href="tools.ietf.org/html/draft-ietf-hip-hiccups">HIP Immediate
 * Carriage and Conveyance of Upper-layer Protocol Signaling
 * (HICCUPS)</a>. In a nutshell, HICCUPS can be used to replace
 * encryption of data plane using IPsec symmetric key encryption with
 * public key encryption. The dataplane is carried over HIP control
 * packets until either end-host sends an R1 and then the end-hosts
 * switch to IPsec. An end-host can also switch to IPsec immediately
 * without processing any HICCUPS packet by sending an R1. This file
 * implements inbound and outbound processing of the dataplane similarly
 * to the userspace IPsec.
 *
 * @todo Some features from HICCUPS are still missing (switch to IPsec,
 *        SEQ numbers).
 * @todo The implementation is not optimized for speed
 *
 * @brief Implementation of HICCUPS extensions (data packets)
 *
 * @author Prabhu Patil
 */

#define _BSD_SOURCE

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/hostid.h"
#include "lib/core/ife.h"
#include "lib/core/message.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "cache.h"
#include "firewall_defines.h"
#include "user_ipsec_api.h"
#include "user_ipsec_esp.h"
#include "datapkt.h"

