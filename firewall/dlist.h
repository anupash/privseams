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

struct dlist *append_to_list(struct dlist *list, void *data);

struct dlist *remove_link_dlist(struct dlist *list, struct dlist *link);

struct dlist *insert_to_list(struct dlist *list, void *data,
                             unsigned int index);

struct dlist *find_in_dlist(struct dlist *list, void *data);

struct dlist *list_last(struct dlist *list);

/* These aren't currently used outside dlist.c, but are declared
   public for uniformity (and so debug-less builds would succeed) */
unsigned int list_length(struct dlist *list);
struct dlist *list_first(struct dlist *list);


#endif /* HIP_FIREWALL_DLIST_H */
