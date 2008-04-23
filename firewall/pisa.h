#ifndef HIP_PISA_H
#define HIP_PISA_H

#include "midauth.h"

/**
 * Register PISA handlers with midauth and initialize data structures.
 *
 * @param h pointer to the handlers
 */
void pisa_init(struct midauth_handlers *h);

#endif

