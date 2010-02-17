#ifndef HIP_FIREWALL_DLIST_H
#define HIP_FIREWALL_DLIST_H

#include <stdlib.h>
#include "common_types.h"
#include "lib/core/debug.h"

DList *alloc_list(void);

void free_list(DList *list);

DList *free_list_chain(DList *list);

DList *append_to_list(DList *list,
                      void *data);

DList *remove_link_dlist(DList *list,
                         DList *link);

DList *remove_from_list(DList *list,
                        const void *data);

DList *insert_to_list(DList *list,
                      void *data,
                      unsigned int index);

DList *find_in_dlist(DList *list,
                     void *data);

DList *list_last(DList *list);

DList *list_first(DList *list);

unsigned int list_length(DList *list);

#endif /*HIP_FIREWALL_DLIST_H*/
