/*
 * signaling_prot_common.c
 *
 *  Created on: Nov 11, 2010
 *      Author: ziegeldorf
 */

#include <string.h>
#include <stdlib.h>

#include "lib/core/debug.h"
#include "signaling_prot_common.h"

static void signaling_param_appinfo_print_field(const char *prefix, const uint16_t length, const unsigned char *p_content) {
    char *buf;

    if(length == 0) {
        HIP_DEBUG("%s:\t <empty>.\n", prefix);
        return;
    }

    buf = malloc(length + 1);
    memset(buf, 0, length + 1);
    memcpy(buf, p_content, length);
    HIP_DEBUG("%s:\t%s\n", prefix, buf);
}

void signaling_param_appinfo_print(const struct signaling_param_appinfo *appinfo) {
    const uint8_t *p_content;

    if(appinfo == NULL) {
        HIP_DEBUG("No appinfo parameter given.\n");
        return;
    }

    p_content = (const uint8_t *) appinfo + sizeof(struct signaling_param_appinfo);
    signaling_param_appinfo_print_field("Application DN:", ntohs(appinfo->app_dn_length), p_content);
    p_content += ntohs(appinfo->app_dn_length);
    signaling_param_appinfo_print_field("Issuer DN:", ntohs(appinfo->iss_dn_length), p_content);
    p_content += ntohs(appinfo->iss_dn_length);
    signaling_param_appinfo_print_field("Requirements:", ntohs(appinfo->req_length), p_content);
    p_content += ntohs(appinfo->req_length);
    signaling_param_appinfo_print_field("Groups:", ntohs(appinfo->grp_length), p_content);
}
