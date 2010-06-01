/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>
 *
 * Contains one function to get the state of a host association.
 *
 * @author Miika Komu <miika@iki.fi>
 */

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/icomm.h"
#include "lib/core/ife.h"
#include "lib/core/message.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "firewall.h"
#include "common_hipd_msg.h"

