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
      printf("ip: '%s' newip: '%s'\n",ip,newip); //test line 
      if( strcmp(ip,newip) )
	{
	  printf("IP/HIT was not found from the openDHT (%s)\n",ip);
	  // The ip from get doesn't match the one from update
	  if( (ret = opendhtputhit(hit,ip)) )
	    {
	      printf("Error: Could not Put returned: %d",ret);
	      //free(newip);
	      return 1;
	    }
	}
      else
	{
	  printf("Value exists in DHT (%s)\n",newip);
	}
      //free(newip);
      return 0;      
    }
  else
    {
      printf("We should put the HIT/IP\n");
      
      if( (ret = opendhtputhit(hit,ip)) )
	{
	  printf("Error: Could not Put returned: %d",ret);
          //free(newip);
	  return 1;
	}
    }
  //free(newip);  
  return 0;
}

int updateMAPS(char *fqdn, char *hit, char *ip) 
{
  int ret;
  char *dht_val = malloc(sizeof(char[40])); 
  
  //informative part checks that the mappings really are in the openDHT 
  dht_val[0] = '\0';
  if( opendhtgetbyhitmultiple(fqdn, hit, dht_val) == 0 )  
  {
    //printf("hit: '%s' dht_val: '%s'\n",hit,dht_val); //test line 
    if( strcmp(hit,dht_val) )
    {
      printf("TEST: Fqdn->HIT was not found from the DHT (%s->%s)\n",fqdn, hit);
      //HIP_DEBUG("Fqdn->HIT was not found from the DHT (%s->%s)\n",fqdn, hit);
    }
    else
    {
      printf("TEST: Fqdn->HIT mapping exists in the DHT (%s->%s)\n",fqdn, hit);
      //HIP_DEBUG("Fqdn->HIT mapping exists in the DHT (%s->%s)\n",fqdn, hit);
    }
  }
  else
  {
    printf("TEST: Fqdn->HIT was not found from the DHT (%s->%s)\n",fqdn, hit);
    //HIP_DEBUG("Fqdn->HIT was not found from the DHT (%s->%s)\n",fqdn, hit);
  }
  
  dht_val[0] = '\0';
  if( opendhtgetbyhitmultiple(hit, ip, dht_val) == 0 )  
  {
    //printf("ip: '%s' dht_val: '%s'\n",ip,dht_val); //test line 
    if( strcmp(ip,dht_val) )
    {
      printf("TEST: HIT->IP was not found from the DHT (%s->%s)\n",hit, ip);
      //HIP_DEBUG("HIT->IP was not found from the DHT (%s->%s)\n",hit, ip);
    }
    else
    {
      printf("TEST: HIT->IP mapping exists in the DHT (%s->%s)\n",hit, ip);
      //HIP_DEBUG("HIT->IP mapping exists in the DHT (%s->%s)\n",hit, ip);
    }
  }
  else
  {
   printf("TEST: HIT->IP was not found from the DHT (%s->%s)\n",hit, ip);
    //HIP_DEBUG("HIT->IP was not found from the DHT (%s->%s)\n",hit, ip);
  }
  free(dht_val);
  //end informative part

  //upload mapping fqdn->hit->ip to the DHT
  printf("Upload mapping (fqdn->hit, %s->%s)\n", fqdn, hit);
  //HIP_DEBUG("Upload mapping (fqdn->hit, %s->%s)\n", fqdn, hit);
  if ( ret = opendhtputhit(fqdn,hit) )
  {
    printf("Error: Put (fqdn->hit) failed with return value %d\n", ret);
    //HIP_DEBUG("Error: Put (fqdn->hit) failed with return value %d\n", ret); 
  }
  printf("Upload mapping (hit->ip, %s->%s)\n", hit, ip);
  //HIP_DEBUG("Upload mapping (hit->ip, %s->%s)\n", hit, ip);
  if ( ret = opendhtputhit(hit,ip) )
  {
    printf("Error: Put (hit->ip) failed with return value %d\n", ret);
    //HIP_DEBUG("Error: Put (hit->ip) failed with return value %d\n", ret); 
  }
  return 0;
}
