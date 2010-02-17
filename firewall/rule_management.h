#ifndef HIP_FIREWALL_RULE_MANAGEMENT_H
#define HIP_FIREWALL_RULE_MANAGEMENT_H

#include "dlist.h"
//#include "helpers.h"

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
    int boolean; //0 if negation, else 1
};

struct int_option {
    int value; //int value
    int boolean; // 0 if negation, else 1
};

struct state_option {
    struct int_option int_opt;
    int verify_responder; //1 if responder signatures are verified
    int accept_mobile; //1 if state can be established from updates signalling
    int decrypt_contents;
};

// can be turned to more generic string option if necessary
//
struct string_option {
    char *value;
    int boolean;
};

//Pointer values must be NULL if option is not specified.
//Use alloc_empty_rule() to allocate rule with pointers set to NULL!!
//when updating rule structure, update also (at least) free_rule(),
//print_rule(), rules_equal(), copy_rule (), alloc_empty_rule() functions
struct rule {
    struct hit_option *src_hit;
    struct hit_option *dst_hit;
    struct hip_host_id *src_hi;
    struct int_option *type;
    struct state_option *state;
    struct string_option *in_if;
    struct string_option *out_if;
    unsigned int hook;
    int accept;
};

/*-------------- RULES ------------*/

//void print_rule(const struct rule * rule);
void print_rule_tables(void);

void read_rule_file(const char *file_name);
DList *read_rules(const int hook);
void read_rules_exit(const int hook);

#endif
