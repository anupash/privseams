#ifndef lib_opendht

#define lib_opendht

/* Resolve the gateway address using opendht.nyuld.net */
#define DHT_PORT 5851

int init_dht_gateway_socket(int);
int resolve_dht_gateway_info(char *, struct addrinfo *);
int connect_dht_gateway(int, struct addrinfo *);
int opendht_put(int, unsigned char *, unsigned char *, unsigned char *);
int opendht_get(int, unsigned char *, unsigned char *);
int opendht_read_response(int, char *);

#endif /* lib_opendht */
