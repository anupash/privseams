#include <stdio.h>
#include <string.h>
#include "dhtresolver.h"

#include <opendht_interface.h>


int gethiphostbyhit(char *hit, char *ip)
{

   if(strlen(hit) > 40) // Check if the HIT has the correct length
    {
      printf("Incorrect HIT!\n");
      return 1;
    }

  if( opendhtgetbyhit(hit,ip) )
    {
      printf("Could not get %s\n",hit);
      return 1;
    }
  return 0;
}

int gethiphostbyname(char *fqdn, char *hit)
{  
  // Missing: Some checks for the domain is correct

  if( opendhtgetbyname(fqdn, hit) )
    {
      printf("Could not get %s\n",fqdn);
      return 1;
    }
  
  return 0;
}
