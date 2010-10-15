/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
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
