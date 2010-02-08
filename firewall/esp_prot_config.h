/**
 * @file firewall/esp_prot_config.h
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * API for reading of the configuration files for the
 * ESP protection extension. It furthermore provides sanity
 * checks on the passed values.
 *
 * @brief Reads the config file for the ESP protection extension
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#ifndef ESP_PROT_CONFIG_H_
#define ESP_PROT_CONFIG_H_

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

/* WORKAROUND: some platforms don't support libconfig out of the box */
#ifdef HAVE_LIBCONFIG
#include <libconfig.h>
#else
typedef struct
{
	// this is just defined to satisfy dependencies
} config_t;
#endif

config_t * esp_prot_read_config(void);
int esp_prot_release_config(config_t *cfg);
int esp_prot_token_config(const config_t *cfg);
int esp_prot_sender_config(const config_t *cfg);
int esp_prot_verifier_config(const config_t *cfg);

#endif /* ESP_PROT_CONFIG_H_ */
