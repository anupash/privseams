/** @file
 * A header file for libhipopendhtxml.c
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * All xml-rpc message building functions for opendht.
 * Also contains base 64 encoding and decoding wrappers that should
 * be moved somewhere else because they are used also in cert stuff.
 *
 * @author Samu Varjonen
 *
 */

#ifndef HIP_LIB_DHT_LIBHIPDHTXML_H
#define HIP_LIB_DHT_LIBHIPDHTXML_H

/* All XML RPC packet creation and reading functions */

int build_packet_put_rm(unsigned char *, int, unsigned char *,
                        int, unsigned char *, int, int, unsigned char *,
                        char *, int);

int build_packet_put(unsigned char *, int, unsigned char *,
                     int, int, unsigned char *, char *, int);

int build_packet_get(unsigned char *, int, int, unsigned char *, char *);

int build_packet_rm(unsigned char *, int, unsigned char *,
                    int, unsigned char *, int, int, unsigned char *,
                    char *, int);

int read_packet_content(char *, char *);

struct opendht_answers {
    int  count;
    char addrs[440];
};

#endif /* HIP_LIB_DHT_LIBHIPDHTXML_H */
