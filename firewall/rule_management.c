/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * Writes a default firewall ACL configuration file. Reads and parses
 * the configuration from disk to memory.
 *
 * @brief HIP firewall ACL rules management
 *
 * @author Essi Vehmersalo
 */

#define _BSD_SOURCE

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <openssl/dsa.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/hostid.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "dlist.h"
#include "firewall.h"
#include "helpers.h"
#include "rule_management.h"


/* string tokens for rule parsing */
#define SRC_HIT_STR "-src_hit"
#define DST_HIT_STR "-dst_hit"
#define TYPE_STR "-type"
#define IN_IF_STR "-i"
#define OUT_IF_STR "-o"
#define STATE_STR "-state"
#define SRC_HI_STR "--hi"
#define VERIFY_RESPONDER_STR "--verify_responder"
#define ACCEPT_MOBILE_STR "--accept_mobile"
#define DECRYPT_CONTENTS_STR "--decrypt_contents"
#define NEGATE_STR "!"
#define INPUT_STR "INPUT"
#define OUTPUT_STR "OUTPUT"
#define FORWARD_STR "FORWARD"
#define NEW_STR "NEW"
#define ESTABLISHED_STR "ESTABLISHED"
/* filename needs to contain either to be valid HI file */
#define RSA_FILE "_rsa_"
#define DSA_FILE "_dsa_"

#define MAX_LINE_LENGTH 512

#define HIP_FW_DEFAULT_RULE_FILE HIPL_SYSCONFDIR "/firewall_conf"
#define HIP_FW_CONFIG_FILE_EX \
    "# format: HOOK [match] TARGET\n" \
    "#   HOOK   = INPUT, OUTPUT or FORWARD\n" \
    "#   TARGET = ACCEPT or DROP\n" \
    "#   match  = -src_hit [!] <hit value> --hi <file name>\n" \
    "#            -dst_hit [!] <hit>\n" \
    "#            -type [!] <hip packet type>\n" \
    "#            -i [!] <incoming interface>\n" \
    "#            -o [!] <outgoing interface>\n" \
    "#            -state [!] <state> --verify_responder --accept_mobile --decrypt_contents\n" \
    "#\n" \
    "\n"


enum {
    NO_OPTION,
    SRC_HIT_OPTION,
    DST_HIT_OPTION,
    SRC_HI_OPTION,
    DST_HI_OPTION,
    TYPE_OPTION,
    STATE_OPTION,
    IN_IF_OPTION,
    OUT_IF_OPTION,
    HOOK
};

DList *input_rules;
DList *output_rules;
DList *forward_rules;

/**
 * Writes the default firewall configuration file to the disk if it does
 * not exist
 *
 * @file
 */
static void check_and_write_default_config(const char *file)
{
    struct stat status;
    FILE *fp = NULL;
    ssize_t items;
    int i    = 0;

    /* Firewall depends on hipd to create /etc/hip */
    for (i = 0; i < 5; i++) {
        if (stat(HIPL_SYSCONFDIR, &status) &&
            errno == ENOENT) {
            HIP_INFO("%s does not exist. Waiting for hipd to start...\n",
                     HIPL_SYSCONFDIR);
            sleep(2);
        } else {
            break;
        }
    }

    if (i == 5) {
        HIP_DIE("Please start hipd or execute 'hipd -c'\n");
    }

    rename("/etc/hip/firewall.conf", HIP_FW_DEFAULT_RULE_FILE);

    if (stat(file, &status) && errno == ENOENT) {
        errno = 0;
        fp    = fopen(file, "w" /* mode */);
        if (!fp) {
            HIP_PERROR("Failed to write config file\n");
        }
        HIP_ASSERT(fp);
        items = fwrite(HIP_FW_CONFIG_FILE_EX,
                       strlen(HIP_FW_CONFIG_FILE_EX), 1, fp);
        HIP_ASSERT(items > 0);
        fclose(fp);
    }
}

/**
 * accessor function to get the rule list of the given iptables hook
 *
 * @param hook NF_IP6_LOCAL_IN, NF_IP6_LOCAL_OUT or NF_IP6_LOCAL_FORWARD
 * @return a pointer to the list containing the rules
 */
static DList *get_rule_list(const int hook)
{
    if (hook == NF_IP6_LOCAL_IN) {
        return input_rules;
    } else if (hook == NF_IP6_LOCAL_OUT) {
        return output_rules;
    } else {
        return forward_rules;
    }
}

/*------------- PRINTING -----------------*/

/**
 * display (or log) the given rule for diagnostics
 *
 * @param the rule to be displayed
 */
static void print_rule(const struct rule *rule)
{
    if (rule != NULL) {
        HIP_DEBUG("rule: ");
        /* filtering firewall, so no other hooks supported */
        if (rule->hook == NF_IP6_LOCAL_IN) {
            HIP_DEBUG("%s ", INPUT_STR);
        } else if (rule->hook == NF_IP6_LOCAL_OUT) {
            HIP_DEBUG("%s ", OUTPUT_STR);
        } else {
            HIP_DEBUG("%s ", FORWARD_STR);
        }

        if (rule->src_hit != NULL) {
            HIP_DEBUG("%s ", SRC_HIT_STR);
            if (!rule->src_hit->boolean) {
                HIP_DEBUG("%s ", NEGATE_STR);
            }
            HIP_DEBUG("%s ", addr_to_numeric(&rule->src_hit->value));
        }
        if (rule->dst_hit != NULL) {
            HIP_DEBUG("%s ", DST_HIT_STR);
            if (!rule->dst_hit->boolean) {
                HIP_DEBUG("%s ", NEGATE_STR);
            }
            HIP_DEBUG("%s ", addr_to_numeric(&rule->dst_hit->value));
        }
        if (rule->src_hi != NULL) {
            HIP_DEBUG("src_hi exists ");
        }
        if (rule->type != NULL) {
            HIP_DEBUG(" %s ", TYPE_STR);
            if (!rule->type->boolean) {
                HIP_DEBUG("%s ", NEGATE_STR);
            }
            HIP_DEBUG("%d ", rule->type->value);
        }
        if (rule->state != NULL) {
            HIP_DEBUG("%s ", STATE_STR);
            if (!rule->state->int_opt.boolean) {
                HIP_DEBUG("%s ", NEGATE_STR);
            }
            HIP_DEBUG("%d ", rule->state->int_opt.value);
            if (rule->state->verify_responder) {
                HIP_DEBUG("%s ", VERIFY_RESPONDER_STR);
            }
            if (rule->state->accept_mobile) {
                HIP_DEBUG("%s ", ACCEPT_MOBILE_STR);
            }
            if (rule->state->decrypt_contents) {
                HIP_DEBUG("%s ", DECRYPT_CONTENTS_STR);
            }
        }
        if (rule->in_if != NULL) {
            HIP_DEBUG("%s ", IN_IF_STR);
            if (!rule->in_if->boolean) {
                HIP_DEBUG("%s ", NEGATE_STR);
            }
            HIP_DEBUG("%s ", rule->in_if->value);
        }
        if (rule->out_if != NULL) {
            HIP_DEBUG("%s ", OUT_IF_STR);
            if (!rule->out_if->boolean) {
                HIP_DEBUG("%s ", NEGATE_STR);
            }
            HIP_DEBUG("%s ", rule->out_if->value);
        }
        if (rule->accept) {
            HIP_DEBUG("ACCEPT\n");
        } else {
            HIP_DEBUG("DROP\n");
        }
    }
}

/**
 * Display (or log) all rule tables for diagnostics
 *
 * @note: caller should take care of synchronization
 */
void print_rule_tables(void)
{
    struct _DList *list = (struct _DList *) input_rules;
    struct rule *rule   = NULL;
    while (list != NULL) {
        rule = (struct rule *) list->data;
        print_rule(rule);
        list = list->next;
    }
    list = (struct _DList *) output_rules;
    while (list != NULL) {
        rule = (struct rule *) list->data;
        print_rule(rule);
        list = list->next;
    }
    list = (struct _DList *) forward_rules;
    while (list != NULL) {
        rule = (struct rule *) list->data;
        print_rule(rule);
        list = list->next;
    }
}

/*------------- ALLOCATING & FREEING -----------------*/

/**
 * Allocates empty rule structure and sets elements to NULL
 *
 * @return The allocated rule. Caller frees.
 */
static struct rule *alloc_empty_rule(void)
{
    struct rule *rule = malloc(sizeof(struct rule));
    rule->src_hit = NULL;
    rule->dst_hit = NULL;
    rule->src_hi  = NULL;
    rule->type    = NULL;
    rule->state   = NULL;
    rule->in_if   = NULL;
    rule->out_if  = NULL;
    rule->hook    = -1;
    rule->accept  = -1;
    return rule;
}

/**
 * Deallocate a string option
 *
 * @param string the string option to be deallocated
 */
static void free_string_option(struct string_option *string)
{
    if (string) {
        free(string->value);
        free(string);
    }
}

/**
 * Deallocate a rule structure and all non NULL members
 *
 * @rule the rule to be deallocated
 */
static void free_rule(struct rule *rule)
{
    if (rule) {
        HIP_DEBUG("freeing ");
        print_rule(rule);
        if (rule->src_hit != NULL) {
            free(rule->src_hit);
        }
        if (rule->dst_hit != NULL) {
            free(rule->dst_hit);
        }
        if (rule->src_hi != NULL) {
            free(rule->src_hi);
        }
        if (rule->type != NULL) {
            free(rule->type);
        }
        if (rule->state != NULL) {
            free(rule->state);
        }
        if (rule->in_if != NULL) {
            free_string_option(rule->in_if);
        }
        if (rule->out_if != NULL) {
            free_string_option(rule->out_if);
        }
        free(rule);
    }
}

/*---------------PARSING---------------*/

/**
 * convert a HIT from character to numeric format
 *
 * @param token character array contains a HIT and possible a
 *        negatation (separated by space)
 *
 * @return a hit_option structure (caller frees)
 */
static struct hit_option *parse_hit(char *token)
{
    struct hit_option *option = malloc(sizeof(struct hit_option));
    struct in6_addr *hit      = NULL;

    if (!strcmp(token, NEGATE_STR)) {
        option->boolean = 0;
        token           = (char *) strtok(NULL, " ");
    } else {
        option->boolean = 1;
    }
    hit = (struct in6_addr *) numeric_to_addr(token);
    if (hit == NULL) {
        HIP_DEBUG("parse_hit error\n");
        free(option);
        return NULL;
    }
    option->value = *hit;
    HIP_DEBUG_HIT("hit ok: ", hit);
    return option;
}

/**
 * load an RSA public key from a file and convert it into a hip_host_id
 *
 * @param fp FILE object where to load a PEM formatted RSA public key
 *
 * @return hip_host id structure (caller deallocates) or NULL on error
 */
static struct hip_host_id *load_rsa_file(FILE *fp)
{
    struct hip_host_id *hi    = NULL;
    RSA *rsa                  = NULL;
    unsigned char *rsa_key_rr = NULL;
    int rsa_key_rr_len;

    rsa = RSA_new();
    rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
    if (!rsa) {
        HIP_DEBUG("reading RSA file failed \n");
        RSA_free(rsa);
        return NULL;
    }
    rsa_key_rr     = malloc(sizeof(struct hip_host_id));
    rsa_key_rr_len = rsa_to_dns_key_rr(rsa, &rsa_key_rr);
    hi             = malloc(sizeof(struct hip_host_id));
    hip_build_param_host_id_hdr(hi, NULL, rsa_key_rr_len, HIP_HI_RSA);
    hip_build_param_host_id_only(hi, rsa_key_rr, NULL);

    return hi;
}

/**
 * load an DSA public key from a file and convert it into a hip_host_id
 *
 * @param fp FILE object where to load a PEM formatted DSA public key
 *
 * @return hip_host id structure (caller deallocates) or NULL on error
 */
static struct hip_host_id *load_dsa_file(FILE *fp)
{
    struct hip_host_id *hi    = NULL;
    DSA *dsa                  = NULL;
    unsigned char *dsa_key_rr = NULL;
    int dsa_key_rr_len;

    dsa = DSA_new();
    dsa = PEM_read_DSA_PUBKEY(fp, &dsa, NULL, NULL);
    if (!dsa) {
        HIP_DEBUG("reading RSA file failed \n");
        DSA_free(dsa);
        return NULL;
    }
    dsa_key_rr     = malloc(sizeof(struct hip_host_id));
    dsa_key_rr_len = dsa_to_dns_key_rr(dsa, &dsa_key_rr);
    hi             = malloc(sizeof(struct hip_host_id));
    hip_build_param_host_id_hdr(hi, NULL, dsa_key_rr_len, HIP_HI_DSA);
    hip_build_param_host_id_only(hi, dsa_key_rr, NULL);
    return hi;
}

/**
 * load a public key from a file and convert it to a hip_host_id structure
 *
 * @param token the file where the DSA or RSA public key is located in PEM format
 * @param hit the HIT corresponding to the public key
 *
 * @return a hip_host_id structure which the caller must deallocate
 * @note token file name must have _dsa_ or _rsa_ in the file to distinguish the algorithm
 */
static struct hip_host_id *parse_hi(char *token, const struct in6_addr *hit)
{
    FILE *fp = NULL;
    int algo;
    struct hip_host_id *hi = NULL;
    struct in6_addr temp_hit;

    HIP_DEBUG("parse_hi: hi file: %s\n", token);
    fp = fopen(token, "rb");
    if (!fp) {
        HIP_DEBUG("Invalid filename for HI \n");
        return NULL;
    }
    if (strstr(token, RSA_FILE)) {
        algo = HIP_HI_RSA;
    } else if (strstr(token, DSA_FILE)) {
        algo = HIP_HI_DSA;
    } else {
        HIP_DEBUG("Invalid filename for HI: missing _rsa_ or _dsa_ \n");
        return NULL;
    }
    if (algo == HIP_HI_RSA) {
        hi = load_rsa_file(fp);
    } else {
        hi = load_dsa_file(fp);
    }
    if (!hi) {
        HIP_DEBUG("file loading failed \n");
        return NULL;
    }

    /* verify hi => hit */
    hip_host_id_to_hit(hi, &temp_hit, HIP_HIT_TYPE_HASH100);
    if (ipv6_addr_cmp(&temp_hit, hit)) {
        HIP_DEBUG("HI in file %s does not match hit %s \n",
                  token, addr_to_numeric(hit));
        free(hi);
        return NULL;
    }
    return hi;
}

/**
 * convert control parameter type from string to numeric format
 *
 * @token the type as a character array
 *
 * @return The type as a numeric int_option structure or NULL on error.
 *         The caller is responsible to deallocate the return value.
 */
static struct int_option *parse_type(char *token)
{
    struct int_option *option = malloc(sizeof(struct int_option));

    if (!strcmp(token, NEGATE_STR)) {
        option->boolean = 0;
        token           = (char *) strtok(NULL, " ");
    } else {
        option->boolean = 1;
    }
    HIP_DEBUG("type token %s \n", token);
    if (!strcmp(token, "I1")) {
        option->value = HIP_I1;
    } else if (!strcmp(token, "R1")) {
        option->value = HIP_R1;
    } else if (!strcmp(token, "I2")) {
        option->value = HIP_I2;
    } else if (!strcmp(token, "R2")) {
        option->value = HIP_R2;
    } else if (!strcmp(token, "CER")) {
        option->value = HIP_CER;
    } else if (!strcmp(token, "UPDATE")) {
        option->value = HIP_UPDATE;
    } else if (!strcmp(token, "NOTIFY")) {
        option->value = HIP_NOTIFY;
    } else if (!strcmp(token, "CLOSE")) {
        option->value = HIP_CLOSE;
    } else if (!strcmp(token, "CLOSE_ACK")) {
        option->value = HIP_CLOSE_ACK;
    } else if (!strcmp(token, "PAYLOAD")) {
        option->value = HIP_PAYLOAD;
    } else {
        HIP_DEBUG("parse_type error\n");
        free(option);
        return NULL;
    }
    return option;
}

/**
 * convert a string into a numeric state_option structure
 *
 * @param token the state_option structure as a char array
 *
 * @return a state_option structure which the caller must free,
 *         or NULL on error
 */
static struct state_option *parse_state(char *token)
{
    struct state_option *option = malloc(sizeof(struct state_option));

    if (!strcmp(token, NEGATE_STR)) {
        option->int_opt.boolean = 0;
        token                   = (char *) strtok(NULL, " ");
    } else {
        option->int_opt.boolean = 1;
    }
    if (!strcmp(token, NEW_STR)) {
        option->int_opt.value = CONN_NEW;
    } else if (!strcmp(token, ESTABLISHED_STR)) {
        option->int_opt.value = CONN_ESTABLISHED;
    } else {
        HIP_DEBUG("parse_state error\n");
        free(option);
        return NULL;
    }
    option->verify_responder = 0;
    option->accept_mobile    = 0;
    option->decrypt_contents = 0;
    return option;
}

/**
 * convert an interface name to numeric representation format
 *
 * @param token the interface name as char array
 *
 * @return the interface name as a string_option structure (caller deallocates) or
 *         NULL on error
 */
static struct string_option *parse_if(char *token)
{
    struct string_option *option = malloc(sizeof(struct string_option));

    if (!strcmp(token, NEGATE_STR)) {
        option->boolean = 0;
        token           = (char *) strtok(NULL, " ");
    } else {
        option->boolean = 1;
    }
    if (strlen(token) > IF_NAMESIZE) {
        HIP_DEBUG("parse_if error: invalid length interface name\n");
        free(option);
        return NULL;
    } else {
        option->value = malloc(IF_NAMESIZE);
        strcpy(option->value, token);
    }
    return option;
}

/**
 * parse a string into a rule structure
 *
 * @param a string containing a rule
 *
 * @return pointer to allocated rule structure (caller
 *         deallocates or NULL on error)
 */
static struct rule *parse_rule(char *string)
{
    struct rule *rule = NULL;
    char *token;
    int option_found  = NO_OPTION;

    token = (char *) strtok(string, " ");
    if (token == NULL) {
        return NULL;
    }
    rule  = alloc_empty_rule();
    /* rule needs to start with a hook */
    if (!strcmp(token, INPUT_STR)) {
        rule->hook = NF_IP6_LOCAL_IN;
    } else if (!strcmp(token, OUTPUT_STR)) {
        rule->hook = NF_IP6_LOCAL_OUT;
    } else if (!strcmp(token, FORWARD_STR)) {
        rule->hook = NF_IP6_FORWARD;
    } else {
        HIP_DEBUG("rule is missing netfilter hook\n");
        free_rule(rule);
        return NULL;
    }
    while (strlen(string) > 0) {
        token = (char *) strtok(NULL, " ");
        if (token == NULL) {
            /* empty string */
            break;
        }
        /* matching new option */
        else if (option_found == NO_OPTION) {
            if (!strcmp(token, SRC_HIT_STR)) {
                /* option already defined */
                if (rule->src_hit != NULL) {
                    HIP_DEBUG("error parsing rule: src_hit option \n");
                    free_rule(rule);
                    return NULL;
                }
                option_found = SRC_HIT_OPTION;
            } else if (!strcmp(token, DST_HIT_STR))      {
                /* option already defined */
                if (rule->dst_hit != NULL) {
                    HIP_DEBUG("error parsing rule: dst_hit option \n");
                    free_rule(rule);
                    return NULL;
                }
                option_found = DST_HIT_OPTION;
            } else if (!strcmp(token, SRC_HI_STR))      {
                /* option already defined */
                if (rule->src_hit == NULL || /* no hit for hi */
                    !rule->src_hit->boolean || /* negated hit */
                    rule->src_hi != NULL) { /* hi already defined */
                    HIP_DEBUG("error parsing rule: src_hi option \n");
                    free_rule(rule);
                    return NULL;
                }
                option_found = SRC_HI_OPTION;
            } else if (!strcmp(token, TYPE_STR))      {
                /* option already defined */
                if (rule->type != NULL) {
                    HIP_DEBUG("error parsing rule: type option \n");
                    free_rule(rule);
                    return NULL;
                }
                option_found = TYPE_OPTION;
            } else if (!strcmp(token, STATE_STR))      {
                /* option already defined */
                if (rule->state != NULL) {
                    HIP_DEBUG("error parsing rule: state option \n");
                    free_rule(rule);
                    return NULL;
                }
                option_found = STATE_OPTION;
            } else if (!strcmp(token, VERIFY_RESPONDER_STR))      {
                /* related state option must be defined */
                if (rule->state == NULL) {
                    HIP_DEBUG("error parsing rule: %s without %s\n",
                              VERIFY_RESPONDER_STR, STATE_STR);
                    free_rule(rule);
                    return NULL;
                }
                rule->state->verify_responder = 1;
            } else if (!strcmp(token, ACCEPT_MOBILE_STR))      {
                /* related state option must be defined */
                if (rule->state == NULL) {
                    HIP_DEBUG("error parsing rule: %s without %s\n",
                              ACCEPT_MOBILE_STR, STATE_STR);
                    free_rule(rule);
                    return NULL;
                }
                rule->state->accept_mobile = 1;
            } else if (!strcmp(token, DECRYPT_CONTENTS_STR))      {
                /* related state option must be defined */
                if (rule->state == NULL) {
                    HIP_DEBUG("error parsing rule: %s without %s\n",
                              DECRYPT_CONTENTS_STR, STATE_STR);
                    free_rule(rule);
                    return NULL;
                }
                rule->state->decrypt_contents = 1;
            } else if (!strcmp(token, IN_IF_STR))      {
                /* option already defined */
                /* rule in output hook can't have incoming if */
                if (rule->in_if != NULL || rule->hook == NF_IP6_LOCAL_OUT) {
                    HIP_DEBUG("error parsing rule: i option \n");
                    free_rule(rule);
                    return NULL;
                }
                option_found = IN_IF_OPTION;
            } else if (!strcmp(token, OUT_IF_STR))      {
                /* option already defined */
                /* rule in input hook can't have outcoming if */
                if (rule->in_if != NULL || rule->hook == NF_IP6_LOCAL_IN) {
                    HIP_DEBUG("error parsing rule: o option \n");
                    free_rule(rule);
                    return NULL;
                }
                option_found = OUT_IF_OPTION;
            } else if (!strcmp(token, "ACCEPT"))      {
                /* target already defined */
                if (rule->accept > -1) {
                    HIP_DEBUG("error parsing rule: target \n");
                    free_rule(rule);
                    return NULL;
                }
                rule->accept = 1;
                break;
            } else if (!strcmp(token, "DROP"))      {
                /* target already defined */
                if (rule->accept > -1) {
                    HIP_DEBUG("error parsing rule: target \n");
                    free_rule(rule);
                    return NULL;
                }
                rule->accept = 0;
                break;
            } else {
                /* invalid option */
                HIP_DEBUG("error parsing rule: invalid option %s\n", token);
                free_rule(rule);
                return NULL;
            }
        } else {
            /* matching value for previous option */
            if (option_found == SRC_HIT_OPTION) {
                rule->src_hit = parse_hit(token);
                if (rule->src_hit == NULL) {
                    HIP_DEBUG("error parsing rule: src_hit value \n");
                    free_rule(rule);
                    return NULL;
                }
                option_found = NO_OPTION;
            } else if (option_found == DST_HIT_OPTION)      {
                rule->dst_hit = parse_hit(token);
                if (rule->dst_hit == NULL) {
                    HIP_DEBUG("error parsing rule: dst_hit value \n");
                    free_rule(rule);
                    return NULL;
                }
                option_found = NO_OPTION;
            }
            if (option_found == SRC_HI_OPTION) {
                rule->src_hi = parse_hi(token, &rule->src_hit->value);
                if (rule->src_hi == NULL) {
                    HIP_DEBUG("error parsing rule: src_hi value \n");
                    free_rule(rule);
                    return NULL;
                }
                option_found = NO_OPTION;
            } else if (option_found == TYPE_OPTION)      {
                rule->type = parse_type(token);
                if (rule->type == NULL) {
                    HIP_DEBUG("error parsing rule: type value \n");
                    free_rule(rule);
                    return NULL;
                }
                option_found = NO_OPTION;
            } else if (option_found == STATE_OPTION)      {
                rule->state = parse_state(token);
                if (rule->state == NULL) {
                    HIP_DEBUG("error parsing rule: state value \n");
                    free_rule(rule);
                    return NULL;
                }
                option_found = NO_OPTION;
            } else if (option_found == IN_IF_OPTION)      {
                rule->in_if = parse_if(token);
                if (rule->in_if == NULL) {
                    HIP_DEBUG("error parsing rule: i value \n");
                    free_rule(rule);
                    return NULL;
                }
                option_found = NO_OPTION;
            } else if (option_found == OUT_IF_OPTION)      {
                rule->out_if = parse_if(token);
                if (rule->out_if == NULL) {
                    HIP_DEBUG("error parsing rule: o value \n");
                    free_rule(rule);
                    return NULL;
                }
                option_found = NO_OPTION;
            }
        }
    }
    /* rule must have a verdict */
    if (rule->accept == -1) {
        free_rule(rule);
        HIP_DEBUG("error parsing rule: rule is missing ACCEPT/DROP\n");
        return NULL;
    }
    /* verdict must be the last part */
    if (strtok(NULL, " ") != NULL) {
        free_rule(rule);
        HIP_DEBUG("error parsing rule: ACCEPT/DROP must be last part of rule\n");
        return NULL;
    }

    //print_rule(rule);
    return rule;
}

/*-----------PARSING ----------*/

/**
 * a wrapper to get_rule_list()
 *
 * @param hook the input, output or forward hook
 *
 * @return a list containing the rules
 */
DList *read_rules(const int hook)
{
    return (DList *) get_rule_list(hook);
}

/*----------- RULE MANAGEMENT -----------*/

/*
 * when rules are changed also statefulFiltering value in
 * firewall.c must be updated with set_stateful_filtering()
 */

/**
 * read a rule line in the firewall configuration file
 *
 * @param buf the buffer where the line is read
 * @param buflen the length of the buffer
 * @param file a handle to the firewall configuration file
 *
 * @return the length of the line (excluding trailing \0)
 * @todo check correctness of this function
 */
static size_t read_line(char *buf, int buflen, FILE *file)
{
    int ch     = 0;
    size_t len = 0;

    HIP_ASSERT(file != 0);
    HIP_ASSERT(buf != 0);
    HIP_ASSERT(buflen > 0);

    if (fgets(buf, buflen, file) == NULL) {
        if (feof(file)) {               /* EOF */
            len = 0;
        } else {                        /* error */
            len = 0;
        }
        clearerr(file);
        return len;
    }

    len = strlen(buf);
    if (buf[len - 1] == '\n') {         /* clear any trailing newline */
        buf[--len] = '\0';
    } else if (len == buflen - 1) {     /* line too long */
        while ((ch = getchar()) != '\n' && ch != EOF) {
            continue;
        }
        clearerr(file);
        return 0;
    }

    return len;
}

/**
 * read all rule sets from the specified file and parse into rule
 * lists
 *
 * @param file_name the name of the configuration file to be read
 *
 * @todo fix reading of empty lines (memory problems)
 */
void read_rule_file(const char *file_name)
{
    DList *input        = NULL;
    DList *output       = NULL;
    DList *forward      = NULL;
    FILE *file          = NULL;
    struct rule *rule   = NULL;
    char line[MAX_LINE_LENGTH];
    char *original_line = NULL;
    int s               = MAX_LINE_LENGTH;
    int state           = 0;
    size_t line_length  = 0;
    char *tmp_line      = NULL;

    if (!file_name) {
        file_name = HIP_FW_DEFAULT_RULE_FILE;
    }

    check_and_write_default_config(file_name);

    HIP_DEBUG("read_file: file %s\n", file_name);
    file = fopen(file_name, "r");

    if (file != NULL) {
        while ((line_length = read_line(line, s, file)) > 0) {
            char *comment;

            original_line = malloc(line_length + sizeof(char) + 1);
            original_line = strcpy(original_line, line);

            HIP_DEBUG("line read: %s\n", line);

            /* terminate the line to comment sign */
            comment = index(line, '#');
            if (comment) {
                *comment = 0;
            }

            if (line_length == 0) {
                free(original_line);
                continue;
            }

            /* remove trailing new line */
            tmp_line = (char *) strtok(line, "\n");

            if (tmp_line) {
                rule = parse_rule(tmp_line);
            }

            if (rule) {
                if (rule->state) {
                    state = 1;
                }

                if (rule->hook == NF_IP6_LOCAL_IN) {
                    input = (DList *) append_to_list((DList *) input,
                                                     (void *) rule);
                    print_rule((struct rule *) ((DList *) input)->data);
                } else if (rule->hook == NF_IP6_LOCAL_OUT)    {
                    output = (DList *) append_to_list((DList *) output,
                                                      (void *) rule);
                    print_rule((struct rule *) ((DList *) output)->data);
                } else if (rule->hook == NF_IP6_FORWARD)    {
                    forward = (DList *) append_to_list((DList *) forward,
                                                       (void *) rule);
                    print_rule((struct rule *) ((DList *) forward)->data);
                }
            } else if (tmp_line)   {
                HIP_DEBUG("unable to parse rule: %s\n", original_line);
            }
            free(original_line);
            original_line = NULL;
        }
        fclose(file);
    } else {
        HIP_DEBUG("Can't open file %s \n", file_name );
    }

    input_rules   = (DList *) input;
    set_stateful_filtering(state);
    output_rules  = (DList *) output;
    forward_rules = (DList *) forward;
}
