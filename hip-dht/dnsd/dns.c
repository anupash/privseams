#include "config.h"
#include "dnsd.h"


int main(void)
{
  int count=0;
  FQDN r[MAXDOMAIN]; // Create structure to store domains in

   count = readConf(r); // Reads config and performs a SHA of the FQDNs
 
   validator(r, 1); // Validate domains and update them into the DHT

}
