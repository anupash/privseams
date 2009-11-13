/** @file
 * A header file for pisa.c.
 *
 * @author Thomas Jansen
 */
#ifndef HIP_PISA_H
#define HIP_PISA_H

#include "midauth.h"

#define PISA_STATE_DISALLOW	0
#define PISA_STATE_ALLOW	1

/**
 * Register PISA handlers with midauth and initialize data structures.
 *
 * @param h pointer to the handlers
 */
void pisa_init(struct midauth_handlers *h);

/**
 * Check if a new random number is necessary.
 */
void pisa_check_for_random_update();

#endif
