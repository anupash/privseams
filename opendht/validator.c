#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "conf.h"
#include "dnsd.h"
#include <opendht_interface.h>

int validator(FQDN* r, int count)
{
  int i, ret;
  char *result = malloc(sizeof(char[40]));

  for(i=0;i<count;i++)
    {
     printf("Updating HIT: %s\n",r[i].HIT);
    
     if( opendhtgetbyname(r[i].domain,result) ) 
       {
	 printf("Could not get sha(fqdn(%s))\n",r[i].domain);
	 return 1;
       }

     printf("Compare '%s' with '%s'",r[i].HIT,result);
     if( strcmp(r[i].HIT,result) )
       {
	 printf("HIT doesnt match, put...\n");
	 if( (ret = opendhtputname(r[i].domain,r[i].HIT)) )
	   {
	     printf("Error: Could not Put returned: %d",ret);
	     return 1;
	   }
	 
       }
     
    }
  return 0;
}

