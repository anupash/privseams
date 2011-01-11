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

#ifndef HIP_FIREWALL_RULE_MANAGEMENT_H
#define HIP_FIREWALL_RULE_MANAGEMENT_H

#include <netinet/in.h>

#include "lib/core/protodefs.h"
#include "dlist.h"

#define DROP 0;
#define ACCEPT 1;

/*-------------- RULES ------------*/

//states for the connection, hip state machine states from hip.h
enum {
    CONN_NEW,
    CONN_ESTABLISHED
};

struct hit_option {
    struct in6_addr value; //hit value
    int             boolean; //0 if negation, else 1
};

struct int_option {
    int value;   /**< int value */
    int boolean; /**< 0 if negation, else 1 */
};

struct state_option {
    struct int_option int_opt;
    int               verify_responder; /**< 1 if responder signatures are verified */
    int               accept_mobile; /**< 1 if state can be established from updates signalling */
    int               decrypt_contents;
};

// can be turned to more generic string option if necessary
//
struct string_option {
    char *value;
    int   boolean;
};

// Pointer values must be NULL if option is not specified.
// Use alloc_empty_rule() to allocate rule with pointers set to NULL!!
// when updating rule structure, update also (at least) free_rule(),
// print_rule(), rules_equal(), copy_rule (), alloc_empty_rule() functions
struct rule {
    struct hit_option    *src_hit;
    struct hit_option    *dst_hit;
    struct hip_host_id   *src_hi;
    struct int_option    *type;
    struct state_option  *state;
    struct string_option *in_if;
    struct string_option *out_if;
    unsigned int          hook;
    int                   accept;
};

/*-------------- RULES ------------*/
void print_rule_tables(void);

void read_rule_file(const char *file_name);
struct dlist *get_rule_list(const int hook);

#endif /* HIP_FIREWALL_RULE_MANAGEMENT_H */
