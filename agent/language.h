/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/
#ifndef LANGUAGE_H
#define LANGUAGE_H

#include "debug.h"
#include "str_var.h"
#include "agent/tools.h"

int lang_init(const char *, const char *);
char *lang_get(const char *);

#endif /* LANGUAGE_H */

