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

/**
 * @file
 * API for reading of the configuration files for the
 * ESP protection extension. It furthermore provides sanity
 * checks on the passed values.
 *
 * @brief Reads the config file for the ESP protection extension
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#ifndef HIP_FIREWALL_ESP_PROT_CONFIG_H
#define HIP_FIREWALL_ESP_PROT_CONFIG_H

#include "config.h"

/* WORKAROUND: some platforms don't support libconfig out of the box */
#ifdef HAVE_LIBCONFIG
#include <libconfig.h>
#else
typedef struct {
    // this is just defined to satisfy dependencies
} config_t;
#endif

config_t *esp_prot_read_config(void);
int esp_prot_release_config(config_t *cfg);
int esp_prot_token_config(const config_t *cfg);
int esp_prot_sender_config(const config_t *cfg);
int esp_prot_verifier_config(const config_t *cfg);

#endif /* HIP_FIREWALL_ESP_PROT_CONFIG_H */
