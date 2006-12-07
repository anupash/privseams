#ifndef lib_opendht

#define lib_opendht

/* Resolve the gateway address using opendht.nyuld.net */
#define DHT_PORT 5851

struct sockaddr_in * resolve_dht_gateway();
int resolve_dht_gateway_info(char *, sa_family_t);
int opendht_put_b(int, unsigned char *, unsigned char *, unsigned char *, char *);
int opendht_get_b(int, unsigned char *, unsigned char *, char *);
int opendht_read_response_b(int, char *);
/* For TEST purposes - Prints explanation of return code to stdout */
void print_explanation(int);

#endif lib_opendht
