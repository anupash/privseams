#ifndef DOXYGEN_H
#define DOXYGEN_H
/**
 * @file
 *
 * There should be no need to include this file anywhere! This is only for
 * defining doxygen related things, such as groups and lists.
 */

/**
 * @mainpage
 * Welcome to Host Identity Protocol for Linux (HIPL) Doxygen page.
 *
 * @section sec_doc Project Documents
 * <ul>
 * <li><a href="http://hipl.hiit.fi/index.php?index=source">HIPL source code</a></li>
 * <li><a href="http://bazaar.launchpad.net/~hipl-core/hipl/trunk/files">Web-based version control browser</a></li>
 * <li>doc/HACKING. This file contains developer information on policies in the
 * HIPL project.</li>
 * <li>HIPL User Manual. Run <code>make doc/HOWTO.html</code> to generate it.</li>.
 * Periodically prebuilt <a href="http://hipl.hiit.fi/hipl/manual/index.html">manual</a>
 * is also available (from the trunk branch).
 * <li><a href="https://bugs.launchpad.net/hipl/">Launchpad bug tracker</a></li>
 * <!--<li><a href=""></a>.</li>-->
 * </ul>
 *
 * @section sec_links Links
 * <ul>
 * <li><a href="http://infrahip.hiit.fi/">Project home page</a>.</li>
 * </ul>
 * <ul>
 * <li><a href="http://linux.die.net/man/">Linux Man Pages</a>. See section 3
 *     for C-library functions.</li>
 * <li><a href="http://www.cppreference.com/">C/C++ Reference</a>.</li>
 * <li><a href="http://www.acm.uiuc.edu/webmonkeys/book/c_guide/">The C Library Reference Guide</a> by Eric Huss.</li>
 * <li><a href="http://tigcc.ticalc.org/doc/keywords.html">C Language Keywords</a>.</li>
 * </ul>
 * <ul>
 * <li><a href="http://www.dinkumware.com/manuals/default.aspx?manual=compleat&page=index.html#Standard%20C%20Library">Standard C Library</a>
 *     by Dinkumware Ltd.</li>
 * <li><a href="http://www.crasseux.com/books/ctutorial/">The GNU C Programming Tutorial</a>.</li>
 * <li><a href="http://www.greenend.org.uk/rjk/2001/02/cfu.html">C Language Gotchas</a>.
 *     A description of some easy-to-make mistakes in C.</li>
 * <li><a href="http://www.greenend.org.uk/rjk/2003/03/inline.html">Inline Functions In C</a>.
 *     Notes on GCC and standard C inline functions.</li>
 * <li><a href="http://docs.freebsd.org/info/gcc/gcc.info.Variable_Attributes.html">Specifying Attributes of Variables</a>.
 *     Information about specifying special attributes of variables or structure
 *     fields. For example, what does the <code>__attribute__ ((packed))</code>
 *     after a structure definition really mean.</li>
 * <li><a href="http://c-faq.com/">Frequently Asked Questions</a> at comp.lang.c.</li>
 * </ul>
 * <ul>
 * <li><a href="http://www.docbook.org/tdg/en/html/">DocBook: The Definitive Guide</a>.</li>
 * A guide for the @b docbook tool that is used to create the HIPL user manual.
 * </ul>
 *
 * @section sec_faq Frequently asked questions (FAQ)
 * @subsection subsec_socket The Socket Interface
 * <p>Since the socket interface issues keep on popping up, we have gathered
 *     links related to <code>sockaddr</code>, <code>sockaddr_in</code>,
 *     <code>sockaddr_in6</code> and <code>sockaddr_storage</code> data
 *     structures here.</p>
 *     <ul>
 *     <li><a href="http://www.rfc-editor.org/rfc/rfc2553.txt">
 *     RFC 2553: Basic Socket Interface Extensions for IPv6</a>.</li>
 *     <li><a href="http://www.kame.net/newsletter/19980604/">
 *     Implementing AF-independent application</a>. A document that describes
 *     how a programmer can handle multiple address families at ease.
 *     </li>
 *     <li>
 *     <code>sockaddr_in</code> is defined in /usr/include/linux/in.h. See
 *     <a href="http://linux.die.net/man/7/ip">ip(7) - Linux man page</a>.
 *     <pre>
 *     struct sockaddr_in {
 *            sa_family_t    sin_family;
 *            __be16         sin_port;
 *            struct in_addr sin_addr;
 *            unsigned char  __pad[__SOCK_SIZE__ - sizeof(short int) -
 *                           sizeof(unsigned short int) - sizeof(struct in_addr)];
 *     };</pre>
 *     </li>
 *     <li>
 *     <code>sockaddr_in6</code> is defined in /usr/include/linux/in6.h. See
 *     <a href="http://linux.die.net/man/7/ipv6">ipv6(7) - Linux man page</a>.
 *     <pre>
 *     struct sockaddr_in6 {
 *            unsigned short int sin6_family;
 *            __be16             sin6_port;
 *            __be32             sin6_flowinfo;
 *           struct in6_addr     sin6_addr;
 *           __u32               sin6_scope_id;
 *     };</pre>
 *     </li>
 *     <li>
 *     <code>sockaddr</code> is defined in /usr/include/linux/socket.h.
 *     See <a href="http://linux.die.net/man/7/socket">socket(7) - Linux man
 *     page</a>.
 *     <pre>
 *     struct sockaddr {
 *            sa_family_t sa_family;
 *            char        sa_data[14];
 *     };</pre>
 *     </li>
 *     <li>
 *     <code>sockaddr_storage</code> is defined in /usr/include/linux/socket.h.
 *     See <a href="http://linux.die.net/man/7/socket">socket(7) - Linux man
 *     page</a>.
 *     <pre>
 *     struct sockaddr_storage {
 *            unsigned short ss_family;
 *            char     __data[_K_SS_MAXSIZE - sizeof(unsigned short)];
 *     } __attribute__ ((aligned(_K_SS_ALIGNSIZE)));</pre>
 *     </li>
 *     </ul>
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

#endif /* DOXYGEN_H */
