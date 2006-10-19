#ifndef _DOXYGEN_H
#define _DOXYGEN_H
/** @file
 * There should be no need to include this file anywhere!
 * This is only for defining doxygen related things, such as
 * groups and lists.
 */
 
/**
 * Error handling macros used for checking errors. To use these macros, define a
 * label named @c out_err at the end of the function. For example, memory
 * allocation/deallocation procedure is as follows:
 * <pre>
 * int f() {
 *     char *mem = NULL;
 *     HIP_IFEL(!(mem = HIP_ALLOC(256, 0)), -1, "alloc\n");
 * 
 *   out_err:
 *     if (mem)
 *       free(mem);
 *     return err;
 * }
 * </pre>
 * All functions should return an error value instead of "ok" value. That, is
 * zero for success and non-zero for failure. Error values are defined in
 * /usr/include/asm-generic/errno-base.h and /usr/include/asm-generic/errno.h
 * as follows:
 *
 * <pre>
 * EPERM            1       Operation not permitted 
 * ENOENT           2       No such file or directory 
 * ESRCH            3       No such process 
 * EINTR            4       Interrupted system call 
 * EIO              5       I/O error 
 * ENXIO            6       No such device or address 
 * E2BIG            7       Argument list too long 
 * ENOEXEC          8       Exec format error 
 * EBADF            9       Bad file number 
 * ECHILD          10       No child processes 
 * EAGAIN          11       Try again 
 * ENOMEM          12       Out of memory 
 * EACCES          13       Permission denied 
 * EFAULT          14       Bad address 
 * ENOTBLK         15       Block device required 
 * EBUSY           16       Device or resource busy 
 * EEXIST          17       File exists 
 * EXDEV           18       Cross-device link 
 * ENODEV          19       No such device 
 * ENOTDIR         20       Not a directory 
 * EISDIR          21       Is a directory 
 * EINVAL          22       Invalid argument 
 * ENFILE          23       File table overflow 
 * EMFILE          24       Too many open files 
 * ENOTTY          25       Not a typewriter 
 * ETXTBSY         26       Text file busy 
 * EFBIG           27       File too large 
 * ENOSPC          28       No space left on device 
 * ESPIPE          29       Illegal seek 
 * EROFS           30       Read-only file system 
 * EMLINK          31       Too many links 
 * EPIPE           32       Broken pipe 
 * EDOM            33       Math argument out of domain of func 
 * ERANGE          34       Math result not representable 
 * EDEADLK         35       Resource deadlock would occur
 * ENAMETOOLONG    36       File name too long
 * ENOLCK          37       No record locks available
 * ENOSYS          38       Function not implemented
 * ENOTEMPTY       39       Directory not empty
 * ELOOP           40       Too many symbolic links encountered
 * EWOULDBLOCK     EAGAIN   Operation would block
 * ENOMSG          42       No message of desired type
 * EIDRM           43       Identifier removed
 * ECHRNG          44       Channel number out of range
 * EL2NSYNC        45       Level 2 not synchronized
 * EL3HLT          46       Level 3 halted
 * EL3RST          47       Level 3 reset
 * ELNRNG          48       Link number out of range
 * EUNATCH         49       Protocol driver not attached
 * ENOCSI          50       No CSI structure available
 * EL2HLT          51       Level 2 halted
 * EBADE           52       Invalid exchange
 * EBADR           53       Invalid request descriptor
 * EXFULL          54       Exchange full
 * ENOANO          55       No anode
 * EBADRQC         56       Invalid request code
 * EBADSLT         57       Invalid slot
 * EDEADLOCK       EDEADLK
 * EBFONT          59       Bad font file format
 * ENOSTR          60       Device not a stream
 * ENODATA         61       No data available
 * ETIME           62       Timer expired
 * ENOSR           63       Out of streams resources
 * ENONET          64       Machine is not on the network
 * ENOPKG          65       Package not installed
 * EREMOTE         66       Object is remote
 * ENOLINK         67       Link has been severed
 * EADV            68       Advertise error
 * ESRMNT          69       Srmount error
 * ECOMM           70       Communication error on send
 * EPROTO          71       Protocol error
 * EMULTIHOP       72       Multihop attempted
 * EDOTDOT         73       RFS specific error
 * EBADMSG         74       Not a data message
 * EOVERFLOW       75       Value too large for defined data type
 * ENOTUNIQ        76       Name not unique on network
 * EBADFD          77       File descriptor in bad state
 * EREMCHG         78       Remote address changed
 * ELIBACC         79       Can not access a needed shared library
 * ELIBBAD         80       Accessing a corrupted shared library
 * ELIBSCN         81       .lib section in a.out corrupted
 * ELIBMAX         82       Attempting to link in too many shared libraries
 * ELIBEXEC        83       Cannot exec a shared library directly
 * EILSEQ          84       Illegal byte sequence
 * ERESTART        85       Interrupted system call should be restarted
 * ESTRPIPE        86       Streams pipe error
 * EUSERS          87       Too many users
 * ENOTSOCK        88       Socket operation on non-socket
 * EDESTADDRREQ    89       Destination address required
 * EMSGSIZE        90       Message too long
 * EPROTOTYPE      91       Protocol wrong type for socket
 * ENOPROTOOPT     92       Protocol not available
 * EPROTONOSUPPORT 93       Protocol not supported
 * ESOCKTNOSUPPORT 94       Socket type not supported
 * EOPNOTSUPP      95       Operation not supported on transport endpoint
 * EPFNOSUPPORT    96       Protocol family not supported
 * EAFNOSUPPORT    97       Address family not supported by protocol
 * EADDRINUSE      98       Address already in use
 * EADDRNOTAVAIL   99       Cannot assign requested address
 * ENETDOWN        100      Network is down
 * ENETUNREACH     101      Network is unreachable
 * ENETRESET       102      Network dropped connection because of reset
 * ECONNABORTED    103      Software caused connection abort
 * ECONNRESET      104      Connection reset by peer
 * ENOBUFS         105      No buffer space available
 * EISCONN         106      Transport endpoint is already connected
 * ENOTCONN        107      Transport endpoint is not connected
 * ESHUTDOWN       108      Cannot send after transport endpoint shutdown
 * ETOOMANYREFS    109      Too many references: cannot splice
 * ETIMEDOUT       110      Connection timed out
 * ECONNREFUSED    111      Connection refused
 * EHOSTDOWN       112      Host is down
 * EHOSTUNREACH    113      No route to host
 * EALREADY        114      Operation already in progress
 * EINPROGRESS     115      Operation now in progress
 * ESTALE          116      Stale NFS file handle
 * EUCLEAN         117      Structure needs cleaning
 * ENOTNAM         118      Not a XENIX named type file
 * ENAVAIL         119      No XENIX semaphores available
 * EISNAM          120      Is a named type file
 * EREMOTEIO       121      Remote I/O error
 * EDQUOT          122      Quota exceeded
 * ENOMEDIUM       123      No medium found
 * EMEDIUMTYPE     124      Wrong medium type
 * ECANCELED       125      Operation Canceled
 * ENOKEY          126      Required key not available
 * EKEYEXPIRED     127      Key has expired
 * EKEYREVOKED     128      Key has been revoked
 * EKEYREJECTED    129      Key was rejected by service
 * EOWNERDEAD      130      Owner died
 * ENOTRECOVERABLE 131      State not recoverable
 * </pre>
 *
 * @defgroup ife Error handling macros
 **/

/** @defgroup params TODOs for parameters */

/**
 * @defgroup hip_msg HIP daemon message types
 * @note DONT MAKE THESE VALUES HIGHER THAN 255.
 *       The variable, which stores this type, is 8 bits.
 */

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
 * @defgroup hip_param_type_numbers HIP parameter type values
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

/** 
 * Functions for receiving HIP control packets.
 * 
 * These functions are called after a HIP control packet is received by
 * hip_receive_control_packet()-function and the packet is detected to be a HIP
 * control packet. The purpose of these functions is to decide whether to
 * handle the packet at all. This decision is based first and foremost on the
 * state of the current host association. If the packet is to be handled, all
 * handling should be done in respective handle-function.
 * 
 * @defgroup receive_functions HIP receive functions
 * @see      handle_functions
 */

/** 
 * Functions for handling HIP control packets.
 *
 * These functions do the actual handling of the packet. These functions are
 * called from the corresponding receive functions. 
 * 
 * @defgroup handle_functions HIP handle functions
 * @see      receive_functions
 */

#endif /* _DOXYGEN_H */
