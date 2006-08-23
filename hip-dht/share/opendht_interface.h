
// Resolve IP-address from HITs
int opendhtgetbyhit(char *,char *); 

// Resolve IP-address from HITs (multiple IPs)
int opendhtgetbyhitmultiple(char *, char *, char *);

// Resolve IP-addresses fromo FQDNs
int opendhtgetbyname(char *,char *); 

// Puts HIT with new IP
int opendhtputhit(char *,char *);

//TTL 
#define TTL 60*4 
