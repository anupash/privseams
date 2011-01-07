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

#ifndef HIP_LIB_CORE_IFE_H
#define HIP_LIB_CORE_IFE_H

#include "debug.h"

/** A generic HIP error. This should be a value whose value does not overlap
 *  with the global errno values. */
#define EHIP       500
/** A generic error value for getaddrinfo() error since the negated library
 *  error values overlap ernno values. */
#define EHADDRINFO 501

/**
 * @addtogroup ife
 * @{
 */

/**
 * Use this macro to detect failures and exit function in case
 * of such. Variable 'err' must be defined, usually type int.
 * Label 'out_err' must be defined, on errors this label is used
 * as destination after proper actions.
 *
 * @param func Nonzero, if failure.
 * @param eval Set variable called 'err' to this value.
 */
#define HIP_IFE(func, eval) \
    { \
        if (func) { \
            err = eval; \
            goto out_err; \
        } \
    }

/**
 * Use this macro to detect failures and exit function in case
 * of such. Variable 'err' must be defined, usually type int.
 * Label 'out_err' must be defined, on errors this label is used
 * as destination after proper actions.
 *
 * @param func Nonzero, if failure.
 * @param eval Set variable called 'err' to this value.
 * @param args Arguments for HIP_ERROR(), use like with printf().
 */
#define HIP_IFEL(func, eval, args ...) \
    { \
        if (func) { \
            HIP_ERROR(args); \
            err = eval; \
            goto out_err; \
        } \
    }

#define HIP_IFEB(func, eval, finally) \
    { \
        if (func) { \
            err = eval; \
            finally; \
            goto out_err; \
        } else { \
            finally; \
        } \
    }

#define HIP_IFF(func, eval, finally, args ...) \
    { \
        if (func) { \
            HIP_ERROR(args); \
            err = eval; \
            finally; \
            goto out_err; \
        } \
    }

/** @} */

#endif /* HIP_LIB_CORE_IFE_H */
