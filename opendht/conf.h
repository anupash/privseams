#define MAXDOMAIN 20

struct hitFQDN
{
 char domain[255]; //domain 
 char HIT[50]; //Hit encoded in SHA-1
};

typedef struct hitFQDN FQDN;

int readConf(FQDN *);
