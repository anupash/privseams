#ifndef HIP_FIREWALL_HSLIST_H
#define HIP_FIREWALL_HSLIST_H

#include <stdlib.h>
#include "common_types.h"

SList *alloc_slist(void);

void free_slist(SList *list);

SList *append_to_slist(SList *list,
                       void *data);

SList *remove_from_slist(SList *list,
                         const void *data);

SList *remove_link_slist(SList *list,
                         SList *link);

SList *slist_last(SList *list);

#endif /*HIP_FIREWALL_HSLIST_H*/
