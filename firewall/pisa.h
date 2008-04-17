#ifndef HIP_PISA_H
#define HIP_PISA_H

#include "midauth.h"

int filter_pisa_i1(ipq_packet_msg_t *m, struct midauth_packet *p);
int filter_pisa_r1(ipq_packet_msg_t *m, struct midauth_packet *p);
int filter_pisa_i2(ipq_packet_msg_t *m, struct midauth_packet *p);
int filter_pisa_r2(ipq_packet_msg_t *m, struct midauth_packet *p);
int filter_pisa_u1(ipq_packet_msg_t *m, struct midauth_packet *p);
int filter_pisa_u2(ipq_packet_msg_t *m, struct midauth_packet *p);
int filter_pisa_u3(ipq_packet_msg_t *m, struct midauth_packet *p);

#endif

