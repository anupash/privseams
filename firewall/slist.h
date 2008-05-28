#ifndef SLIST_H_
#define SLIST_H_

#include "common_types.h"

#include <stdlib.h>

SList * alloc_list (void);

void free_slist (SList * list);

SList * append_to_slist (SList * list,
					    void * data);
					    
SList * remove_from_slist (SList * list,
						   const void * data);
						  
SList * remove_link_slist (SList * list,
						   SList * link);					

SList * slist_last (SList * list);

#endif /*SLIST_H_*/
