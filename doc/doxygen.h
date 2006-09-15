#ifndef _DOXYGEN_H
#define _DOXYGEN_H
/** @file
 * There should be no need to include this file anywhere!
 * This is only for defining doxygen related things, such as
 * groups and lists.
 */
 
/** @defgroup ife Error handling macros */

/** @defgroup params TODOs for parameters */

/** @defgroup hip_msg HIP daemon message types */

/** @defgroup hip_so HIP socket options */

/** @defgroup libhipgui HIP GUI library */

/** @defgroup daemon_states HIP daemon states */

/** 
 * Type values used in Host Identity Protocol (HIP) parameters.
 * 
 * These are the type values used in Host Identity Protocol (HIP) parameters
 * defined in [draft-ietf-hip-base] and other drafts expanding it. Because the
 * ordering (from lowest to highest) of HIP parameters is strictly enforced, the
 * parameter type values for existing parameters have been spaced to allow for
 * future protocol extensions.
 *
 * <b>Type values are grouped as follows:</b>
 * <ul>
 * <li>0-1023 are used in HIP handshake and update procedures and are covered
 * by signatures.</li>
 * <li>1024-2047 are reserved.</li>
 * <li>2048-4095 are used for parameters related to HIP transform types.</li>
 * <li>4096-61439 are reserved. However, a subset (32768 - 49141) of this can be
 * used for HIPL private parameters.</li>
 * <li>61440-62463 are used for signatures and signed MACs.</li>
 * <li>62464-63487 are used for parameters that fall outside of the signed area
 * of the packet.</li>
 * <li>63488-64511 are used for rendezvous and other relaying services.</li>
 * <li>64512-65535 are reserved.</li>
 * </ul>
 * 
 * @defgroup hip_param_type_numbers HIP Parameter Type Values
 * @see      hip_tlv
 * @see      <a href="http://hip4inter.net/documentation/drafts/draft-ietf-hip-base-06-pre180506.txt">
 *           draft-ietf-hip-base-06-pre180506</a> section 5.2.
 * @note     The order of the parameters is strictly enforced. The parameters
 *           @b must be in order from lowest to highest.
 */

/** 
 * Type-length-value data structures in Host Identity Protocol (HIP).
 * 
 * @defgroup hip_tlv HIP TLV data structures
 * @see      hip_param_type_numbers
 * @see      <a href="http://hip4inter.net/documentation/drafts/draft-ietf-hip-base-06-pre180506.txt">
 *           draft-ietf-hip-base-06-pre180506</a> section 5.2.
 * @note     The order of the parameters is strictly enforced. The parameters
 *           @b must be in order from lowest to highest.
 */

/**
 * HIP host assosiation function pointer data structures.
 * 
 * Data structures containing function pointers pointing to functions used for
 * sending, receiving and handling data and modifying host assosiation state.
 * 
 * @defgroup hadb_func HIP host assosiation function sets
 */

#endif /* _DOXYGEN_H */
