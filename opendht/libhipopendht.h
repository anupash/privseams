#ifndef lib_opendht

#define lib_opendht

/* Resolve the gateway address using opendht.nyuld.net */
#define DHT_PORT 5851
#define STATE_OPENDHT_IDLE 0
#define STATE_OPENDHT_WAITING_ANSWER 1
#define STATE_OPENDHT_WAITING_CONNECT 2
#define STATE_OPENDHT_START_SEND 3

int init_dht_gateway_socket(int);
int resolve_dht_gateway_info(char *, struct addrinfo *);
int connect_dht_gateway(int, struct addrinfo *, int);
int opendht_put(int, unsigned char *, unsigned char *, unsigned char *);
int opendht_get(int, unsigned char *, unsigned char *);
int opendht_read_response(int, char *);

#endif /* lib_opendht */
