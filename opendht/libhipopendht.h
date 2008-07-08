#ifndef lib_opendht

#define lib_opendht


/* Resolve the gateway address using opendht.nyuld.net */
//#define OPENDHT_GATEWAY "opendht.nyuld.net"
#define OPENDHT_GATEWAY "openlookup.net"
// change to 5851 XX TODO
#define OPENDHT_PORT 80
// change to 5851 XX TODO
#define OPENDHT_PORT_STR "80" //Not in use
#define OPENDHT_TTL 120
#define STATE_OPENDHT_IDLE 0
#define STATE_OPENDHT_WAITING_ANSWER 1
#define STATE_OPENDHT_WAITING_CONNECT 2
#define STATE_OPENDHT_START_SEND 3
#define OPENDHT_SERVERS_FILE "/etc/hip/dhtservers"
#define OPENDHT_ERROR_COUNT_MAX 3

int init_dht_gateway_socket(int);

int resolve_dht_gateway_info(char *, struct addrinfo **);

int connect_dht_gateway(int, struct addrinfo *, int);

int opendht_put_rm(int, unsigned char *, unsigned char *, 
                   unsigned char *, unsigned char *, int, int);

int opendht_put(int, unsigned char *, unsigned char *, 
                unsigned char *, int, int);

int opendht_rm(int, unsigned char *, unsigned char *,
               unsigned char *, unsigned char *, int, int);

int opendht_get(int, unsigned char *, unsigned char *, int);

/*int opendht_get_key(struct addrinfo *, const unsigned char *,
		    unsigned char *);
*/
int opendht_handle_key(char *, char *);

int opendht_handle_value(char *, char *);


int opendht_read_response(int, char *);

int (*value_handler)(unsigned char * packet, void * answer);  

int handle_hdrr_value (unsigned char *packet, void *hdrr);
int handle_locator_value (unsigned char *packet, void *locator_ipv4);
int handle_hit_value (unsigned char *packet, void *hit); 

#endif /* lib_opendht */
