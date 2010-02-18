/**
 * @file firewall/pisa.h
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @brief A header file for pisa.c
 *
 * @author Thomas Jansen
 */

#ifndef HIP_FIREWALL_PISA_H
#define HIP_FIREWALL_PISA_H

#include "midauth.h"

#define PISA_STATE_DISALLOW     0
#define PISA_STATE_ALLOW        1

/**
 * Register PISA handlers with midauth and initialize data structures.
 *
 * @param h pointer to the handlers
 */
void pisa_init(struct midauth_handlers *h);

/**
 * Check if a new random number is necessary.
 */
void pisa_check_for_random_update(void);

#endif
