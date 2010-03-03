/**
 * @file
 * The header file for hipd/modularization.h
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 *
 * @author Tim Just <tim.just@rwth-aachen.de>
 *
 */
#ifndef HIP_HIPD_MODULARIZATION_H
#define HIP_HIPD_MODULARIZATION_H

int hip_register_handle_function(const uint32_t packet_type,
                                 const uint32_t ha_state,
                                 int (*handle_function)(const uint32_t packet_type,
                                                        const uint32_t ha_state,
                                                        struct hip_packet_context *ctx),
                                 const uint32_t priority);

int hip_unregister_handle_function(const uint32_t packet_type,
                                   const uint32_t ha_state,
                                   const void *handle_function);

int hip_run_handle_functions(const uint32_t packet_type,
                             const uint32_t ha_state,
                             struct hip_packet_context *ctx);

void hip_uninit_handle_functions(void);

int hip_register_maint_function(int (*maint_function)(void),
                                const uint32_t priority);

int hip_run_maint_functions(void);

void hip_uninit_maint_functions(void);

#endif /* HIP_HIPD_MODULARIZATION_H */
