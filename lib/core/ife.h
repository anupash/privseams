/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_LIB_CORE_IFE_H
#define HIP_LIB_CORE_IFE_H

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

#define HIP_IFEBL(func, eval, finally, args ...) \
    { \
        if (func) { \
            HIP_ERROR(args); \
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

/**
 * HIP_IFCS takes a pointer and an command to execute and executes the
 * @c command if @c condition is @b not NULL.
 */
#define HIP_IFCS(condition, consequence) \
    if (condition) {      \
        consequence;      \
    } else {              \
        HIP_DEBUG("No state information found.\n"); \
    }

/** @} */

#endif /* HIP_LIB_CORE_IFE_H */
