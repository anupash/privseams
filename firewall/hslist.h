/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_FIREWALL_HSLIST_H
#define HIP_FIREWALL_HSLIST_H

#include "common_types.h"

SList *append_to_slist(SList *list,
                       void *data);

SList *remove_link_slist(SList *list,
                         SList *link);

#endif /* HIP_FIREWALL_HSLIST_H */
