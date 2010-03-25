/**
 * @file
 * The header file for hipd/pkt_handling.c
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 *
 * @author Tim Just <tim.just@rwth-aachen.de>
 *
 */
#ifndef HIP_HIPD_MODULARIZATION_H
#define HIP_HIPD_MODULARIZATION_H

int hip_register_handle_function(const uint8_t packet_type,
                                 const uint32_t ha_state,
                                 int (*handle_function)(const uint8_t packet_type,
                                                        const uint32_t ha_state,
                                                        struct hip_packet_context *ctx),
                                 const uint16_t priority);

int hip_unregister_handle_function(const uint8_t packet_type,
                                   const uint32_t ha_state,
                                   const void *handle_function);

int hip_run_handle_functions(const uint8_t packet_type,
                             const uint32_t ha_state,
                             struct hip_packet_context *ctx);

void hip_uninit_handle_functions(void);

#endif /* HIP_HIPD_MODULARIZATION_H */
