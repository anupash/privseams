#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dhtresolver.h"
int main(void)
{
  char *hit = malloc(sizeof(char[40]));
  char *ip  = malloc(sizeof(char[40]));

  strcpy(hit,"607e:f207:3d4c:5e89:831b:8ff2:1af5:d618");
  //  strcpy(hit,"1234");
  printf("sizeof hit: %d len: %d \n",sizeof(hit), strlen(hit));

  printf("Teststub for HIP resolver init\n");

  printf("Testing resolver for HIT->IP\n");

  //Calling the resolver function for HIT->IP
  if( gethiphostbyhit(hit,ip) )
    {
      printf("Could not resolve!\n");
      exit(1);
    }

  if(strcmp(ip,""))
    {
      printf("Success! HIT: %s has ip address: %s\n\n",hit,ip);
    }
  else
    {
      printf("Failed!\n");
    }

  //Calling the resolver function for FQDN->HIT
  if( gethiphostbyname("aau.dk",hit) )
    {
      printf("Could not resolve!\n");
      exit(1);
    }

  if(strcmp(hit,""))
    {
      printf("Success! HIT: %s has ip address: %s\n\n",hit,ip);
    }
  else
    {
      printf("Failed!\n");
    }





  free(hit);
  free(ip);

  return 0;
}
