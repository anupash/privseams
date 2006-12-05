/* All XML RPC packet creation functions */

#define TTL "120"

int build_packet_put(unsigned char *, int, unsigned char *, int, int, unsigned char*, char *);

int build_packet_get(unsigned char *, int, int, unsigned char*, char *);

int read_packet_content(char *, char *);

/* openSSL wrapper functions for base64 encoding and decoding */

unsigned char * base64_encode(unsigned char *, unsigned int);

unsigned char * base64_decode(unsigned char *, unsigned int *);

