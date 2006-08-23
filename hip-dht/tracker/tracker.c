#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tracker.h"
#include <opendht_interface.h>

int updateHIT(char *hit, char *ip)
{
  int ret;
  char *newip = malloc(sizeof(char[40])); 
  newip[0] = '\0';

//  if( opendhtgetbyhit(hit, newip) == 0 ) //old
  if( opendhtgetbyhitmultiple(hit, ip, newip) == 0 )  
    {
      //printf("ip: '%s' newip: '%s'\n",ip,newip); //test line 
      if( strcmp(ip,newip) )
	{
	  printf("IP/HIT was not found from the openDHT (%s)\n",ip);
	  // The ip from get doesn't match the one from update
	  if( (ret = opendhtputhit(hit,ip)) )
	    {
	      printf("Error: Could not Put returned: %d",ret);
	      free(newip);
	      return 1;
	    }
	}
      else
	{
	  printf("Value exists in DHT (%s)\n",newip);
	}
      free(newip);
      return 0;      
    }
  else
    {
      printf("We should put the HIT/IP\n");
      
      if( (ret = opendhtputhit(hit,ip)) )
	{
	  printf("Error: Could not Put returned: %d",ret);
          free(newip);
	  return 1;
	}
    }
  free(newip);  
  return 0;
}

