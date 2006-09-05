/* teststub.c - $Revision: 1.5 $
 * 2005-06-25 Per Toft, ComNet6, Aalborg University
 * $DATE$
 * Purpose: Test tool for the HIP tracker
 */

#include <stdio.h>
#include <stdlib.h>
#include "tracker.h"
#include <string.h>


int main(void)
{
  char *hit = malloc(sizeof(char[40]));
  char *ip  = malloc(sizeof(char[40]));

  bzero(ip,sizeof(ip));
  bzero(hit,sizeof(hit));

  strcpy(hit,"607e:f207:3d4c:5e89:831b:8ff2:1af5:d618");
  strcpy(ip,"3ffe:2:0:0:0:0:0:4");

  printf("Teststub for HIP tracker init\n");

  //Calling the update function
  if( updateHIT(hit,ip))
    {
      printf("Could not update!\n");
      exit(1);
    }

  free(ip);
  free(hit);

  return 0;
}

