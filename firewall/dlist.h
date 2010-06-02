/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_FIREWALL_DLIST_H
#define HIP_FIREWALL_DLIST_H

#include "common_types.h"

DList *append_to_list(DList *list,
                      void *data);

DList *remove_link_dlist(DList *list,
                         DList *link);

DList *insert_to_list(DList *list,
                      void *data,
                      unsigned int index);

DList *find_in_dlist(DList *list,
                     void *data);

DList *list_last(DList *list);

/* These aren't currently used outside dlist.c, but are declared
   public for uniformity (and so debug-less builds would succeed) */
unsigned int list_length(DList *list);
DList *list_first(DList *list);


#endif /*HIP_FIREWALL_DLIST_H*/
