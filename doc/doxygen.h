#ifndef _DOXYGEN_H
#define _DOXYGEN_H
/** @file
 * There should be no need to include this file anywhere!
 * This is only for defining doxygen related things, such as
 * groups and lists.
 */

/** @mainpage
 * Welcome to Host Identity Protocol for Linux (HIPL) Doxygen page.
 *
 * @section sec_doc Project Documents
 * <ul>
 * <li>doc/HACKING. This file contains developer information on policies in the HIPL project.</li>
 * <li>HIPL User Manual. Type <code>make HOWTO.html</code> in project root directory.</li> 
 * <!--<li><a href=""></a>.</li>-->
 * </ul>
 * 
 * @section sec_links Links
 * <ul>
 * <li><a href="http://infrahip.hiit.fi/">Project home page</a>.</li>
 * <li><a href="http://linux.die.net/man/">Linux Man Pages</a>. See section 3 for C-library functions.</li>
 * <li><a href="http://www.cppreference.com/">C/C++ Reference</a>.</li>
 * <li><a href="http://tigcc.ticalc.org/doc/keywords.html">C Language Keywords</a>.</li>
 * </ul>
 *
 * @date   04.09.2007
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
 *     if (mem != NULL) {
 *       free(mem);
 *     }
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
 * @note <span style="color:#f00">Don't make these values higher than 255.</span>
 *       The variable, which stores this type, is 8 bits.
 */

/**
 * @file libinet6/protodefs.h
 * @def HIP_I1
 * @def HIP_R1
 * @def HIP_I2
 * @def HIP_R2
 * @def HIP_CER
 * @def HIP_BOS
 * @note removed from ietf-hip-base-01.
 * @def HIP_UPDATE
 * @def HIP_NOTIFY
 * @def HIP_CLOSE
 * @def HIP_CLOSE_ACK
 * @def HIP_PSIG
 *      Lightweight HIP pre signature.
 * @def HIP_TRIG
 *      Lightweight HIP signature trigger.
 * @def HIP_PAYLOAD
 * @def HIP_AGENT_PING
 *      Agent can ping daemon with this message.
 * @def HIP_AGENT_PING_REPLY
 *      Daemon should reply to @c HIP_AGENT_PING with this one.
 * @def HIP_AGENT_QUIT
 *      Agent send this one to daemon when exiting.
 * @def HIP_ADD_DB_HI
 *      Daemon sends local HITs to agent with this message.
 * @def HIP_I1_REJECT
 *      Agent informs daemon about I1 rejection with this message.
 * @def HIP_UPDATE_HIU
 *      Daemon sends remote HITs in use with this message to agent.
 * @def HIP_FIREWALL_PING
 *      Firewall can ping daemon with this message.
 * @def HIP_FIREWALL_PING_REPLY
 *      Daemon should reply to @c HIP_FIREWALL_PING with this one.
 * @def HIP_FIREWALL_QUIT
 *      Firewall sends this one to daemon when exiting.
 * @def HIP_ADD_ESCROW_DATA
 *      Daemon sends escrow data to firewall with this message.
 * @def HIP_DELETE_ESCROW_DATA
 *      Daemon tells firewall to remove escrow data with this message.
 * @def HIP_SET_ESCROW_ACTIVE
 *      Daemon tells firewall that escrow is active with this message.
 * @def HIP_SET_ESCROW_INACTIVE
 *      Daemon tells firewall that escrow is inactive with this message.
 * @def HIP_NAT_ON
 *      Daemon tells, that nat extension status changed.
 * @def HIP_NAT_OFF
 *      Daemon tells, that nat extension status changed.
 * @def HIP_DAEMON_QUIT
 *      Daemon should send this message to other processes, when quiting.
 *      Currently sending to: agent.
 */

/** @defgroup hip_so HIP socket options */

/** @defgroup libhipgui HIP GUI library */

/** @defgroup daemon_states HIP daemon states */

/** @defgroup exec_app_types Execute application types */

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
 * @see      hip_param_func
 * @see      <a href="http://hip4inter.net/documentation/drafts/draft-ietf-hip-base-06-pre180506.txt">
 *           draft-ietf-hip-base-06-pre180506</a> section 5.2.
 * @note     The order of the parameters is strictly enforced. The parameters
 *           @b must be in order from lowest to highest.
 */

/**
 * @file libinet6/protodefs.h
 * @def HIP_PARAM_MIN
 *      Defines the minimum parameter type value.
 * @note exclusive
 * @def HIP_PARAM_ESP_INFO
 * @def HIP_PARAM_R1_COUNTER
 * @def HIP_PARAM_LOCATOR
 * @def HIP_PARAM_HASH_CHAIN_VALUE
 *      lhip hash chain. 221 is is temporary.
 * @def HIP_PARAM_HASH_CHAIN_ANCHORS
 *      lhip hash chain anchors. 222 is temporary.
 * @def HIP_PARAM_HASH_CHAIN_PSIG
 *      lhip hash chain signature. 223 is temporary.
 * @def HIP_PARAM_PUZZLE
 * @def HIP_PARAM_SOLUTION
 * @def HIP_PARAM_SEQ
 * @def HIP_PARAM_ACK
 * @def HIP_PARAM_DIFFIE_HELLMAN
 * @def HIP_PARAM_HIP_TRANSFORM
 * @def HIP_PARAM_ENCRYPTED
 * @def HIP_PARAM_HOST_ID
 * @def HIP_PARAM_CERT
 * @def HIP_PARAM_NOTIFICATION
 * @def HIP_PARAM_ECHO_REQUEST_SIGN
 * @def HIP_PARAM_ECHO_RESPONSE_SIGN
 * @def HIP_PARAM_ESP_TRANSFORM
 * @def HIP_PARAM_HIT
 * @def HIP_PARAM_IPV6_ADDR
 * @def HIP_PARAM_DSA_SIGN_DATA
 * @todo change to digest
 * @def HIP_PARAM_HI
 * @def HIP_PARAM_DH_SHARED_KEY
 * @def HIP_PARAM_UNIT_TEST
 * @def HIP_PARAM_EID_SOCKADDR
 * @def HIP_PARAM_EID_ENDPOINT
 *      Pass endpoint_hip structures into kernel.
 * @def HIP_PARAM_EID_IFACE
 * @def HIP_PARAM_EID_ADDR
 * @def HIP_PARAM_UINT
 *      Unsigned integer.
 * @def HIP_PARAM_KEYS
 * @def HIP_PSEUDO_HIT
 * @def HIP_PARAM_REG_INFO
 * @def HIP_PARAM_REG_REQUEST
 * @def HIP_PARAM_REG_RESPONSE
 * @def HIP_PARAM_REG_FAILED
 * @def HIP_PARAM_BLIND_NONCE
 *      Pass blind nonce
 * @def HIP_PARAM_OPENDHT_GW_INFO
 * @def HIP_PARAM_ENCAPS_MSG
 * @def HIP_PARAM_PORTPAIR
 * @def HIP_PARAM_SRC_ADDR
 * @def HIP_PARAM_DST_ADDR
 * @def HIP_PARAM_AGENT_REJECT
 * @def HIP_PARAM_HA_INFO
 * @def HIP_PARAM_HMAC
 * @def HIP_PARAM_HMAC2
 * @def HIP_PARAM_HIP_SIGNATURE2
 * @def HIP_PARAM_HIP_SIGNATURE
 * @def HIP_PARAM_ECHO_RESPONSE
 * @def HIP_PARAM_ECHO_REQUEST
 * @def HIP_PARAM_RELAY_FROM
 *      HIP relay related parameter.
 * @note Former FROM_NAT.
 * @def HIP_PARAM_RELAY_TO
 *      HIP relay related parameter.
 * @note Former VIA_RVS_NAT
 * @def HIP_PARAM_FROM_PEER
 * @def HIP_PARAM_TO_PEER
 * @def HIP_PARAM_REG_FROM
 * @def HIP_PARAM_FROM
 * @def HIP_PARAM_RVS_HMAC
 * @def HIP_PARAM_VIA_RVS
 * @def HIP_PARAM_RELAY_HMAC
 *      HIP relay related parameter.
 * @def HIP_PARAM_MAX
 *      Defines the maximum parameter type value.
 * @note exclusive
 */

/** 
 * Type-length-value data structures in Host Identity Protocol (HIP).
 * 
 * @defgroup hip_tlv HIP TLV data structures
 * @see      hip_param_type_numbers
 * @see      hip_param_func
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

/** 
 * Functions for creating HIP parameters.
 * 
 * @defgroup hip_param_func HIP parameter functions
 * @see      hip_param_type_numbers
 * @see      hip_tlv
 */

/** 
 * HIP NOTIFICATION parameter values.
 *
 * NOTIFICATION parameter error types used in the "Notify Message Type"-field of
 * NOTIFICATION parameter as specified in section 5.2.16. of
 * draft-ietf-hip-base-06.
 * 
 * @defgroup notification NOTIFICATION parameter values
 * @see      hip_notification 
 */

/**
 * @file libinet6/protodefs.h
 * @def  HIP_NTF_UNSUPPORTED_CRITICAL_PARAMETER_TYPE
 *       Sent if the parameter type has the "critical" bit set and the
 *       parameter type is not recognized.  Notification Data contains the two
 *       octet parameter type.
 * @def  HIP_NTF_INVALID_SYNTAX
 *       Indicates that the HIP message received was invalid because
 *       some type, length, or value was out of range or because the
 *       request was rejected for policy reasons.  To avoid a denial of
 *       service attack using forged messages, this status may only be
 *       returned for packets whose HMAC (if present) and SIGNATURE have
 *       been verified.  This status MUST be sent in response to any
 *       error not covered by one of the other status types, and should
 *       not contain details to avoid leaking information to someone
 *       probing a node.  To aid debugging, more detailed error
 *       information SHOULD be written to a console or log.
 * @def  HIP_NTF_NO_DH_PROPOSAL_CHOSEN
 *       None of the proposed group IDs was acceptable.
 * @def  HIP_NTF_INVALID_DH_CHOSEN
 *       The D-H Group ID field does not correspond to one offered
 *       by the Responder.
 * @def  HIP_NTF_NO_HIP_PROPOSAL_CHOSEN
 *       None of the proposed HIP Transform crypto suites was
 *       acceptable.
 * @def  HIP_NTF_INVALID_HIP_TRANSFORM_CHOSEN
 *       The HIP Transform crypto suite does not correspond to
 *       one offered by the Responder.
 * @def  HIP_NTF_AUTHENTICATION_FAILED
 *       Sent in response to a HIP signature failure, except when
 *       the signature verification fails in a NOTIFY message.
 * @def  HIP_NTF_CHECKSUM_FAILED
 *       Sent in response to a HIP checksum failure.
 * @def  HIP_NTF_HMAC_FAILED
 *       Sent in response to a HIP HMAC failure.
 * @def  HIP_NTF_ENCRYPTION_FAILED
 *       The Responder could not successfully decrypt the
 *       ENCRYPTED parameter.
 * @def  HIP_NTF_INVALID_HIT
 *       Sent in response to a failure to validate the peer's
 *       HIT from the corresponding HI.
 * @def  HIP_NTF_BLOCKED_BY_POLICY
 *       The Responder is unwilling to set up an association
 *       for some policy reason (e.g.\ received HIT is NULL
 *       and policy does not allow opportunistic mode).
 * @def  HIP_NTF_SERVER_BUSY_PLEASE_RETRY
 *       The Responder is unwilling to set up an association
 *       as it is suffering under some kind of overload and
 *       has chosen to shed load by rejecting your request.
 *       You may retry if you wish, however you MUST find
 *       another (different) puzzle solution for any such
 *       retries.  Note that you may need to obtain a new
 *       puzzle with a new I1/R1 exchange.
 * @def  HIP_NTF_I2_ACKNOWLEDGEMENT
 *       The Responder has received your I2 but had to queue
 *       the I2 for processing.  The puzzle was correctly solved
 *       and the Responder is willing to set up an association
 *       but has currently a number of I2s in processing queue.
 *       R2 will be sent after the I2 has been processed.
 * @def  HIP_NTF_RVS_NAT
 *       Sent in response by a Rendezvous Server to a Initiator behind a NAT.
 *       An extension value introduced in draft-schmitt-hip-nat-traversal-03.
 *       In the scenario where a NATted HIP node uses rendezvous service to
 *       contact another HIP node in a publicly addressable network, the
 *       Rendezvous Server replies to the Initiator with a NOTIFY message
 *       having a NOTIFICATION parameter of this type.
 */

/**
 * @defgroup hip_services Additional HIP services. 
 *
 * Registration types for registering to a service as specified in
 * draft-ietf-hip-registration-02. These are the registrationion types used in
 * @c REG_INFO, @c REG_REQUEST, @c REG_RESPONSE and @c REG_FAILED parameters.
 * Numbers 0-200 are reserved by IANA.
 * Numbers 201 - 255 are reserved by IANA for private use.
 */
 
 /** 
 * @file libinet6/protodefs.h
 * @def HIP_SERVICE_RENDEZVOUS
 *      Rendezvous service for relaying I1 packets.
 * @def HIP_SERVICE_ESCROW
 *      Escrow services for some key exchange.
 * @def HIP_SERVICE_RELAY_UDP_HIP
 *      UDP encapsulated relay service for HIP packets.
 * @def HIP_SERVICE_RELAY_UDP_ESP
 *      UDP encapsulated relay service for ESP packets.
 * @def HIP_NUMBER_OF_EXISTING_SERVICES
 *      Total number of services, which must equal the sum of all existing
 *      services.
 */

/**
 * @file   libinet6/protodefs.h
 * @struct hip_rvs_hmac
 *         Rendezvous server hmac. A non-critical parameter whose only difference with
 *         the @c HMAC parameter defined in [I-D.ietf-hip-base] is its @c type code.
 *         This change causes it to be located after the @c FROM parameter (as
 *         opposed to the @c HMAC)
 *
 * @struct hip_from
 *         Parameter containing the original source IP address of a HIP packet.
 * @struct hip_via_rvs
 *         Parameter containing the IP addresses of traversed rendezvous servers.
 * @struct hip_relay_from
 *         Parameter containing the original source IP address and port number
 *         of a HIP packet.
 * @struct hip_relay_to
 *         Parameter containing the IP addresses and source ports of traversed
 *         rendezvous servers.
 * @struct hip_eid_endpoint
 *         This structure is used by the native API to carry local and peer
 *         identities from libc (setmyeid and setpeereid calls) to the HIP
 *         socket handler (setsockopt). It is almost the same as endpoint_hip,
 *         but it is length-padded like HIP parameters to make it usable with
 *         the builder interface.
 */

/**
 * @defgroup hip_ha_controls HIP host association controls.
 *
 * These are bitmasks used in the @c hip_hadb_state stucture fields
 * @c local_controls and @c peer_controls.
 *
 * @local_controls defines the flags of the current host, while peer_controls
 * define the flags of the peer. The flags are used to indicate the state or
 * status of the host. A status can be, for example, that we have requested
 * for a service or that we are capable of offering a service.
 * 
 * Bitmask for local controls:
 * <pre>
 * 0000 0000 0000 0000
 * |||| |||| |||| |||+- 0x0001 - free -
 * |||| |||| |||| ||+-- 0x0002 - free -
 * |||| |||| |||| |+--- 0x0004 - free -
 * |||| |||| |||| +---- 0x0008 - free -
 * |||| |||| |||+------ 0x0010 - free -
 * |||| |||| ||+------- 0x0020 - free -
 * |||| |||| |+-------- 0x0040 - free -
 * |||| |||| +--------- 0x0080 - free -
 * |||| |||+----------- 0x0100 - free -
 * |||| ||+------------ 0x0200 - free -
 * |||| |+------------- 0x0400 - free -
 * |||| +-------------- 0x0800 - free -
 * |||+---------------- 0x1000 - free -
 * ||+----------------- 0x2000 - free -
 * |+------------------ 0x4000 We have requested HIPUDPRELAY service.
 * +------------------- 0x8000 We have requested RVS service.
 * </pre>
 * Bitmask for peer controls:
 * <pre>
 * 0000 0000 0000 0000
 * |||| |||| |||| |||+- 0x0001 - free -
 * |||| |||| |||| ||+-- 0x0002 - free -
 * |||| |||| |||| |+--- 0x0004 - free -
 * |||| |||| |||| +---- 0x0008 - free -
 * |||| |||| |||+------ 0x0010 - free -
 * |||| |||| ||+------- 0x0020 - free -
 * |||| |||| |+-------- 0x0040 - free -
 * |||| |||| +--------- 0x0080 - free -
 * |||| |||+----------- 0x0100 - free -
 * |||| ||+------------ 0x0200 - free -
 * |||| |+------------- 0x0400 - free -
 * |||| +-------------- 0x0800 - free -
 * |||+---------------- 0x1000 - free -
 * ||+----------------- 0x2000 - free -
 * |+------------------ 0x4000 Peer offers HIPUDPRELAY service.
 * +------------------- 0x8000 Peer offers RVS service.
 * </pre>
 *
 * @note There has been some confusion about which bit does what, and which of
 * the control fields to alter. To avoid this confusion, please do not alter
 * the @c local_controls and @c peer_controls fields directly. Instead use
 * functions hip_hadb_set_local_controls(), hip_hadb_set_peer_controls(),
 * hip_hadb_cancel_local_controls(), hip_hadb_cancel_peer_controls().
 */

/**
 * @defgroup hip_packet_controls HIP packet Controls field values.
 *
 * These are the values that are used in the HIP message Controls field. More
 * importantantly, these are <span style="color:#f00;">the only values allowed
 * in that field.</span> Do not put any other bits on wire.
 */

#endif /* _DOXYGEN_H */
