/*
 * esp_prot_conf.h
 *
 *  Created on: 21.09.2009
 *      Author: Rene Hummen
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
#include "libhipcore/debug.h"

config_t * esp_prot_read_config(void);
int esp_prot_release_config(config_t *cfg);
int esp_prot_token_config(config_t *cfg);
int esp_prot_sender_config(config_t *cfg);
int esp_prot_verifier_config(config_t *cfg);

#endif /* ESP_PROT_CONFIG_H_ */
