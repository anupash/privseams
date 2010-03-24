/** @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * HIP-based Internet Indirection Infrastructure (Hi3) code. This code
 * can be used to relay HIP-based traffic over i3 infrastructure.
 * See <a href="http://www.tml.tkk.fi/~pnr/publications/sncnw2004.pdf">
 * Nikander et al, Host Identity Indirection Infrastructure (Hi3), Nov 2004</a>
 * or <a href="http://tools.ietf.org/html/draft-nikander-hiprg-hi3">
 * Nikander et al, Host Identity Indirection Infrastructure (Hi3),
 * June 2004, expired Internet draft</a>.
 *
 * @author Andrey Lukyanenko
 */
/* required for s6_addr32 */
#define _BSD_SOURCE

#include "hi3.h"
//#include "output.h"

#define HI3_TRIGGER_MAX 10

cl_trigger *hi3_pri_tr[HI3_TRIGGER_MAX];
cl_trigger *hi3_pub_tr[HI3_TRIGGER_MAX];

ID hi3_pri_id[HI3_TRIGGER_MAX];
ID hi3_pub_id[HI3_TRIGGER_MAX];
int hi3_pub_tr_count      = 0;
cl_trigger *cl_pub_tr_set = NULL;

static int hip_hi3_add_pub_trigger_id(struct hip_host_id_entry *entry, void *count);
static int hip_hi3_insert_trigger(void);

/**
 * The callback for i3 "no matching id" callback.
 *
 * @param ctx_data a pointer to hi3 ID
 * @param data     a pointer to additional data
 * @param fun_ctx  a pointer to function's context information (not used)
 * @todo           tkoponen: should this somehow trigger the timeout for waiting
 *                 outbound traffic (state machine)?
 */
static void no_matching_trigger(void *ctx_data, void *data, void *fun_ctx)
{
    char id[100];
    sprintf_i3_id(id, (ID *) ctx_data);

    HIP_ERROR("Following ID not found: %s\n", id);
}


/**
 * hi3 initializing function for hip (called from main module)
 *
 * @return 0 on success, terminates program on i3 error
 */
int hip_i3_init()
{
    if (cl_init(HIPL_HI3_FILE) != CL_RET_OK) {
        HIP_ERROR("hi3: error creating context!\n");
        exit(-1);
    }

    cl_register_callback(CL_CBK_TRIGGER_NOT_FOUND, no_matching_trigger, NULL);

    hip_hi3_insert_trigger();


    return 0;
}

/**
 * Adds trigger from defined hip_host_id_entry structure to the list of the available triggers hi3_pub_id
 *
 * @param entry    a pointer to hip_host_id_entry structure
 * @param count    a pointer to the number of triggers in hi3_pub_id array
 * @return 0 on success, negative on the trigger number exceeded
 */
static int hip_hi3_add_pub_trigger_id(struct hip_host_id_entry *entry, void *count)
{
    int i = *(int *) count;
    if (i > HI3_TRIGGER_MAX) {
        HIP_ERROR("Trigger number exceeded");
        return -1;
    }

    bzero(&hi3_pub_id[i], ID_LEN);
    memcpy(&hi3_pub_id[i], &entry->lhi.hit, sizeof(hip_hit_t));
    (*((int *) count))++;

    return 0;
}

/**
 * This is the i3 callback to process received data.
 *
 * @param t  a pointer to cl_trigger (not used right now)
 * @param data a pointer to data received (including padding in the start and end, headers, payload).
 * @param fun_ctx  a pointer to function's context information (not used)
 */
static void hip_hi3_receive_payload(void *t, void *data, void *fun_ctx)
{
    struct hip_common *hip_common;
    // struct hip_work_order *hwo;
    // struct sockaddr_in6 src, dst;
    // struct hi3_ipv4_addr *h4;
    // struct hi3_ipv6_addr *h6;
    // int family, l, type;
    cl_buf *clb = (cl_buf *) data;
    char *buf   = clb->data;
    int len     = clb->data_len;
    hip_portpair_t msg_info;

    /* See if there is at least the HIP header in the packet */
    if (len < sizeof(struct hip_common)) {
        HIP_ERROR("Received packet too small. Dropping\n");
        goto out_err;
    }

    hip_common = (struct hip_common *) buf;
    HIP_DEBUG("Received HIP packet type %d\n", hip_common->type_hdr);
    _HIP_HEXDUMP("HIP PACKET", hip_common,
                 hip_get_msg_total_len(hip_common));

    /*        if (hip_verify_network_header(hip_common,
     *                            (struct sockaddr *)&src,
     *                            (struct sockaddr *)&dst,
     *                            len)) {
     *      HIP_ERROR("Verifying of the network header failed\n");
     *      goto out_err;
     *      }*/

    if (hip_check_network_msg(hip_common)) {
        HIP_ERROR("HIP packet is invalid\n");
        goto out_err;
    }

    memset(&msg_info, 0, sizeof(msg_info));
    msg_info.hi3_in_use = 1;

    struct in6_addr lpback1 = IN6ADDR_LOOPBACK_INIT;
    struct in6_addr lpback2 = IN6ADDR_LOOPBACK_INIT;

    if (hip_receive_control_packet(hip_common, &lpback1, &lpback2, &msg_info, 0)) {
        HIP_ERROR("HIP packet processsing failed\n");
        goto out_err;
    }

out_err:
    //cl_free_buf(clb);
    ;
}

/**
 * i3 callbacks for trigger management (information output)
 *
 * @param t a pointer to cl_trigger struct
 * @param data     a pointer to additional data
 * @param fun_ctx  a pointer to function's context
 */
static void hip_hi3_constraint_failed(void *t, void *data, void *fun_ctx)
{
    /* This should never occur if the infrastructure works */
    HIP_ERROR("Trigger constraint failed\n");
}

/**
 * i3 callbacks for trigger insertion success
 *
 * @param t a pointer to cl_trigger struct
 * @param data     a pointer to additional data
 * @param fun_ctx  a pointer to function's context
 */
static void hip_hi3_trigger_inserted(void *t, void *data, void *fun_ctx)
{
    char id[100];
    cl_trigger *type = (cl_trigger *) t;

    sprintf_i3_id(id, &type->t->id);

    // it should not be error -> info?
    HIP_ERROR("Trigger inserted: %s\n", id);
}

/**
 * i3 callbacks for trigger insert failure
 *
 * @param t a pointer to cl_trigger struct
 * @param data     a pointer to additional data
 * @param fun_ctx  a pointer to function's context
 */
static void hip_hi3_trigger_failure(void *t, void *data, void *fun_ctx)
{
    cl_trigger *type = (cl_trigger *) t;

    /* FIXME: A small delay before trying again? */
    HIP_ERROR("Trigger failed, reinserting...\n");

    /* Reinsert trigger */
    cl_insert_trigger(type, 0);
}

/**
 * The function to insert hi3 specific triggers into i3 network. It defines all callback functions for every new trigger.
 * All triggers IDs are selected from array hi3_pri_id and hi3_pub_id.
 *
 * @return 0 always
 */
static int hip_hi3_insert_trigger(void)
{
    Key key[HI3_TRIGGER_MAX];
    int i;
//  hip_hit_t peer_hit;

    // hip_get_default_hit(&peer_hit);
    // hip_i3_init(/*&peer_hit*/);
    // hi3_pub_tr_count = 1;
    // memcpy(&hi3_pub_id[0], &peer_hit, sizeof(hip_hit_t));
    hip_for_each_hi(hip_hi3_add_pub_trigger_id, &hi3_pub_tr_count );

    for (i = 0; i < hi3_pub_tr_count; i++) {
        get_random_bytes(hi3_pri_id[i].x, ID_LEN);
//      get_random_bytes(key.x, KEY_LEN);

        hi3_pub_tr[i] = cl_create_trigger_id(&hi3_pub_id[i], ID_LEN_BITS, &hi3_pri_id[i],
                                             CL_TRIGGER_CFLAG_R_CONSTRAINT);
//      CL_TRIGGER_CFLAG_L_CONSTRAINT |
//      CL_TRIGGER_CFLAG_PUBLIC);

        cl_register_trigger_callback(hi3_pub_tr[i], CL_CBK_TRIGGER_CONSTRAINT_FAILED,
                                     hip_hi3_constraint_failed, NULL);
        cl_register_trigger_callback(hi3_pub_tr[i], CL_CBK_RECEIVE_PAYLOAD,
                                     hip_hi3_receive_payload, NULL);
        cl_register_trigger_callback(hi3_pub_tr[i], CL_CBK_TRIGGER_INSERTED,
                                     hip_hi3_trigger_inserted, NULL);
        cl_register_trigger_callback(hi3_pub_tr[i], CL_CBK_TRIGGER_REFRESH_FAILED,
                                     hip_hi3_trigger_failure, NULL);


        hi3_pri_tr[i] = cl_create_trigger(&hi3_pri_id[i], ID_LEN_BITS, &key[i],
                                          CL_TRIGGER_CFLAG_R_CONSTRAINT);


        /* associate callbacks with the inserted trigger */
        cl_register_trigger_callback(hi3_pri_tr[i], CL_CBK_TRIGGER_CONSTRAINT_FAILED,
                                     hip_hi3_constraint_failed, NULL);
        cl_register_trigger_callback(hi3_pri_tr[i], CL_CBK_RECEIVE_PAYLOAD,
                                     hip_hi3_receive_payload, NULL);
        cl_register_trigger_callback(hi3_pri_tr[i], CL_CBK_TRIGGER_INSERTED,
                                     hip_hi3_trigger_inserted, NULL);
        cl_register_trigger_callback(hi3_pri_tr[i], CL_CBK_TRIGGER_REFRESH_FAILED,
                                     hip_hi3_trigger_failure, NULL);
    }
    /* Insert triggers */
    for (i = 0; i < hi3_pub_tr_count; i++) {
        cl_insert_trigger(hi3_pri_tr[i], 0);
        cl_insert_trigger(hi3_pub_tr[i], 0);
    }

    return 0;
}

/**
 * The function cleans the triggers before exit. It destroys all triggers inserted into i3 network
 * and cleans i3 context information through cl_exit()
 *
 * @return 0 always
 */
int hip_hi3_clean()
{
    int i = 0;
    for (i = 0; i < hi3_pub_tr_count; i++) {
        cl_destroy_trigger(hi3_pub_tr[i]);
        cl_destroy_trigger(hi3_pri_tr[i]);
    }
    hi3_pub_tr_count = 0;

    cl_exit();

    return 0;
}

/**
 * The function makes sure that "right" locators are inserted into HIP i2 packet, because
 * the hi3 packets goes indirectly through i3 network, both initiator and reponder do not know
 * about any locators of the other station (use IPv4 or IPv6?). This function ensures that the
 * IPs are used in the right order (priority to IPv6) and that they are used correctly (without
 * it HIP assumes that IP addresses already exist on previous stages I1, R1, and it puts address
 * from database which are zeros).
 *
 * @param locator a pointer to hip_locator struct (null if I2 packet missed the field).
 * @param i2_info     a poinjter to info field of I2 packet
 * @param i2_saddr     a pointer to I2 source address
 * @param i2_daddr     a pointer to I2 destination address
 *
 * @return 0 always
 */
int hip_do_i3_stuff_for_i2(struct hip_locator *locator, hip_portpair_t *i2_info,
                           in6_addr_t *i2_saddr, in6_addr_t *i2_daddr)
{
    int n_addrs                              = 0, ii = 0, use_ip4 = 1;
    struct hip_locator_info_addr_item *first = NULL;
    struct netdev_address *n                 = NULL;
    hip_list_t *item                         = NULL, *tmp = NULL;

    if (locator == NULL) {
        return 0;
    }

    if (locator) {
        n_addrs = hip_get_locator_addr_item_count(locator);

        if (i2_info->hi3_in_use && n_addrs > 0) {
            first = (struct hip_locator_info_addr_item *) locator + sizeof(struct hip_locator);
            memcpy(i2_saddr, &first->address,
                   sizeof(struct in6_addr));

            list_for_each_safe(item, tmp, addresses, ii) {
                n = list_entry(item);

                if (ipv6_addr_is_hit(hip_cast_sa_addr((struct sockaddr *) &n->addr))) {
                    continue;
                }
                if (!hip_sockaddr_is_v6_mapped((struct sockaddr *) &n->addr)) {
                    memcpy(i2_daddr, hip_cast_sa_addr((struct sockaddr *) &n->addr),
                           hip_sa_addr_len(&n->addr));
                    ii      = -1;
                    use_ip4 = 0;
                    break;
                }
            }
            if (use_ip4) {
                list_for_each_safe(item, tmp, addresses, ii) {
                    n = list_entry(item);

                    if (ipv6_addr_is_hit(hip_cast_sa_addr((struct sockaddr *) &n->addr))) {
                        continue;
                    }
                    if (hip_sockaddr_is_v6_mapped((struct sockaddr *) &n->addr)) {
                        memcpy(i2_daddr, hip_cast_sa_addr((struct sockaddr *) &n->addr),
                               hip_sa_addr_len(&n->addr));
                        ii = -1;
                        break;
                    }
                }
            }
        }
    }

    return 0;
}
