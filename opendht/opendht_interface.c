#include <stdio.h>
#include <stdlib.h> //a64
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/evp.h>
#include "rpcif.h"
#include "opendht_interface.h"
#include "debug.h"

#define APP_STRING "OpenDHT HIP Interface $Revision: 1.5 $"
#define CLIB_STRING "rpcgen"

//Prototypes
static void do_null_call (CLIENT *);
static CLIENT* connectDHTserver();
int opendhtput(CLIENT* , char* key, char* value, int ttl);
static bamboo_get_res* opendhtget(CLIENT* , bamboo_get_args *, int);

int opendhtgetbyhit(char *hit, char *res)
{
  CLIENT *clnt;
  bamboo_get_args get_args;
  bamboo_get_res  *get_result;
  int key_len;
  char key64[19];
  struct in6_addr addr;

  clnt = connectDHTserver();
  if (clnt == NULL) {
    return 1;
  }

  memset(key64, '\0', sizeof(key64));
  memset (&get_args, 0, sizeof (get_args));

  if (inet_pton(AF_INET6, hit, &addr.s6_addr) == 0) {
    //inet_pton failed so the key was fqdn
    key_len = 0;
    while (hit[key_len] != '\0' && key_len < 39) {
      key_len++;
    }
    if (key_len > 18) {
      key_len = 18;
    }
    EVP_EncodeBlock(key64, hit, key_len);
  } else {
    //key was HIT (IPv6 form)
    unsigned char tmp_key[16];
    memset(tmp_key, 0, sizeof(tmp_key));
    memcpy(tmp_key, addr.s6_addr, sizeof(addr.s6_addr));
    EVP_EncodeBlock(key64, tmp_key, sizeof(addr.s6_addr));
  }

  sprintf(get_args.key, "%s", key64);
  printf("Getting Key: %s (Base64: %s)\n",hit,key64);

  get_result = opendhtget(clnt, &get_args,10); // The 1 indicated the amount of results

  if (get_result == NULL) {
    printf("Get failed\n");
    return 1;
  }

  if (get_result->values.values_len == 0) {
     return 1;
  }

  strncpy(res,get_result->values.values_val [0].bamboo_value_val, get_result->values.values_val [0].bamboo_value_len + 1);
  return 0; //success

}

int opendhtgetbyhitmultiple(char *hit, char *ip, char *res)
{
  CLIENT *clnt;
  bamboo_get_args get_args;
  bamboo_get_res  *get_result;
  int key_len;
  char key64[19];
  struct in6_addr addr;

  clnt = connectDHTserver();
  if (clnt == NULL) {
    return 1;
  }

  memset(key64, '\0', sizeof(key64));
  memset (&get_args, 0, sizeof (get_args));

  if (inet_pton(AF_INET6, hit, &addr.s6_addr) == 0) {
    //inet_pton failed so the key was fqdn
    key_len = 0;
    while (hit[key_len] != '\0' && key_len < 39) {
      key_len++;
    }
    if (key_len > 18) {
      key_len = 18;
    }
    EVP_EncodeBlock(key64, hit, key_len);
  } else {
    //key was HIT (IPv6 form)
    unsigned char tmp_key[16];
    memset(tmp_key, 0, sizeof(tmp_key));
    memcpy(tmp_key, addr.s6_addr, sizeof(addr.s6_addr));
    EVP_EncodeBlock(key64, tmp_key, sizeof(addr.s6_addr));
  }

  sprintf(get_args.key, "%s", key64);

  printf("Getting Key: %s (Base64: %s)\n",hit,key64);

  get_result = opendhtget(clnt, &get_args,10); // The 1 indicated the amount of results

  if (get_result == NULL) {
    printf("Get failed\n");
    return 1;
  }
  
  if (get_result->values.values_len == 0) {
    return 1;
  }

  int j;
  for(j=0;j<get_result->values.values_len;j++) {
    if ( !strcmp(ip, get_result->values.values_val[j].bamboo_value_val) ) {
      //printf("results[%d]: %s\n",j,get_result->values.values_val[j].bamboo_value_val); //test line
       strncpy(res,get_result->values.values_val [j].bamboo_value_val, get_result->values.values_val [0].bamboo_value_len + 1);
    }
  }

  return 0; //success

}

int opendhtgetbyname(char *fqdn, char *res)
{
  CLIENT *clnt;
  bamboo_get_args get_args;
  bamboo_get_res  *get_result;
  int key_len;
  char key64[19];
  struct in6_addr addr;

  clnt = connectDHTserver();
  if (clnt == NULL) {
    return 1;
  }

  memset (key64, '\0', sizeof(key64));
  memset (&get_args, 0, sizeof (get_args));
 
  if (inet_pton(AF_INET6, fqdn, &addr.s6_addr) == 0) {
    //inet_pton failed so the key was fqdn
    key_len = 0;
    while (fqdn[key_len] != '\0' && key_len < 39) {
      key_len++;
    }
    if (key_len > 18) {
      key_len = 18;
    }
    EVP_EncodeBlock(key64, fqdn, key_len);
  } else {
    //key was HIT (IPv6 form)
    unsigned char tmp_key[16];
    memset(tmp_key, 0, sizeof(tmp_key));
    memcpy(tmp_key, addr.s6_addr, sizeof(addr.s6_addr));
    EVP_EncodeBlock(key64, tmp_key, sizeof(addr.s6_addr));
  }
  sprintf(get_args.key, "%s", key64);

  printf("Getting Key: %s (Base64: %s)\n",fqdn,key64);
  //HIP_DEBUG("Getting Key: %s (Base64: %s)\n",key,key64);
  
  get_result = opendhtget(clnt, &get_args,1); // The 1 indicated the amount of results
  
  if (get_result == NULL) {
    printf("Get failed\n");
    return 1;
  }

 if (get_result->values.values_len == 0) {
   return 1;
 }
 strncpy(res,get_result->values.values_val [0].bamboo_value_val, get_result->values.values_val [0].bamboo_value_len + 1);

 int j;

 printf("Got %d results\n", get_result->values.values_len);
// for(j=0;j<get_result->values.values_len;j++) //test line
//     printf("results[%d]: %s\n",j,get_result->values.values_val[j].bamboo_value_val); //test line

  return 0; //success
}

int opendhtputname(char *fqdn, char *hit)
{
  CLIENT *clnt;

  printf("Putting %s with hit %s\n",fqdn,hit);
  //HIP_DEBUG("Putting %s with hit %s\n",fqdn,hit);
  
  sprintf(fqdn,"%ld",a64l(fqdn));

  clnt = connectDHTserver();
  if (clnt == NULL) {
    return 1;
  }

  if(opendhtput(clnt,fqdn,hit,TTL)){
    clnt_destroy (clnt);
    return 1;
  }
  clnt_destroy (clnt);
  return 0; //success
}

static void do_null_call (CLIENT *clnt) 
{
  char *null_args = NULL; 
  void *null_result; 
  printf ("Doing a null call.\n");
  //HIP_DEBUG("Doing a null call.\n");
  null_result = bamboo_dht_proc_null_2((void*)&null_args, clnt);
  if (null_result == (void *) NULL) {
    clnt_perror (clnt, "null call failed.");
    exit (1);
  }
  printf("Null call was successful.\n");
  //HIP_DEBUG("Null call was successful.\n");
}
  
static CLIENT* connectDHTserver(void)
{
  // host and port should be extracted from a file
  char host[] = "planetlab1.diku.dk";
  //char host[] = "opendht.nyuld.net";
  int port = 5852;

  CLIENT *clnt;
  struct sockaddr_in *addr = malloc(sizeof(struct sockaddr_in));
  struct hostent *h;
  int sockp = RPC_ANYSOCK; 
  
  //printf("connecting to %s port %d\n",host, port);
  //HIP_DEBUG("connecting to %s port %d\n",host, port);
  //Lookup server
    h = gethostbyname (host); 
  if (h == NULL) {
    printf("Could not resolve %s\n",host);
    //HIP_DEBUG("Could not resolve %s\n",host);
    //exit(1);
    clnt = NULL;
  }
  //Create sockaddr_in
 // bzero (addr, sizeof (struct sockaddr_in));//old line
  memset(addr, 0, sizeof(struct sockaddr_in));
  addr->sin_family = AF_INET;
  addr->sin_port = htons (port);
  addr->sin_addr = *((struct in_addr *) h->h_addr);
  
  //Connect
  clnt = clnttcp_create (addr, BAMBOO_DHT_GATEWAY_PROGRAM, BAMBOO_DHT_GATEWAY_VERSION, &sockp, 0, 0);
  if (clnt == NULL) {
    clnt_pcreateerror ("Connect failed");
    //exit(1);
  }
  //  do_null_call(clnt);
  free(addr);
  return clnt;
}


int opendhtput(CLIENT* clnt, char* key, char* value, int ttl)
{
  bamboo_put_args put_args;
  bamboo_stat     *put_result;
  int key_len;
  char key64[19];
  struct in6_addr addr;
    
  memset (&put_args, 0, sizeof (put_args));
  memset (key64, '\0', sizeof(key64));
  
  if (inet_pton(AF_INET6, key, &addr.s6_addr) == 0) {
    //inet_pton failed so the key was fqdn
    key_len = 0;
    while (key[key_len] != '\0' && key_len < 39) {
      key_len++;
    }
    if (key_len > 18) {
      key_len = 18;
    }
    EVP_EncodeBlock(key64, key, key_len);
  } else {
    //key was HIT (IPv6 form)
    unsigned char tmp_key[16];
    memset(tmp_key, 0, sizeof(tmp_key));
    memcpy(tmp_key, addr.s6_addr, sizeof(addr.s6_addr));
    EVP_EncodeBlock(key64, tmp_key, sizeof(addr.s6_addr));
  }
  sprintf(put_args.key, "%s", key64);

  printf("Putting Key: %s (Base64: %s) Value: %s TTL: %d\n",key,key64,value,ttl);
  //HIP_DEBUG("Put Key: %s (Base64: %s) Value: %s TTL: %d\n",key,key64,value,ttl);

  put_args.value.bamboo_value_val = value;
  put_args.value.bamboo_value_len = strlen (value);
  put_args.application = APP_STRING;
  put_args.client_library = CLIB_STRING;
  put_args.ttl_sec = ttl;

  put_result = bamboo_dht_proc_put_2 (&put_args, clnt);
  if (put_result == (bamboo_stat *) NULL) {
       clnt_perror (clnt, "Put failed");
       return 1;
  }  
    return 0;
}

int opendhtputhit(char *hit, char *ip)
{
  CLIENT *clnt;
  clnt = connectDHTserver();
  if (clnt == NULL) {
    return 1;
  }

  if(opendhtput(clnt,hit,ip,TTL))
    {
      printf("Could not put %s\n",hit);
      //HIP_DEBUG("Could not put %s",hit);
      clnt_destroy (clnt);
      return 1;
    }
  clnt_destroy (clnt);
  return 0; //success
}

  
static bamboo_get_res* opendhtget(CLIENT* clnt, bamboo_get_args *get_args, int maxvals)
{
  bamboo_get_res  *get_result;

  get_args->application = APP_STRING;
  get_args->client_library = CLIB_STRING;
  get_args->maxvals = maxvals;

  get_result = bamboo_dht_proc_get_2 (get_args, clnt);
  if (get_result == (bamboo_get_res *) NULL) {
    clnt_perror (clnt, "Get failed");
    get_result = NULL;
  }
  
  return get_result;
}

/*
int main (int argc, char *argv[])
{
CLIENT *clnt;
bamboo_get_args get_args;
bamboo_get_res  *get_result;
char host[] =  "planetlab1.diku.dk";
//char host[] = "opendht.nyuld.net";
int port = 5852;
char key[] = "01928491824091";
int ttl = 100;
 char val1[] = "abc";
 int i;

 clnt = connectDHTserver();
 opendhtput(clnt,key,val1,ttl);

 memset (&get_args, 0, sizeof (get_args));
  strcpy(get_args.key,key);
 get_result = opendhtget(clnt, &get_args,1);


 if (get_result->values.values_len == 0) {
   printf ("Get failed: returned %d values.\n", 
	   get_result->values.values_len);
   exit (1);
 }
 for(i=0;i<get_result->values.values_len;i++)
   {
     printf("val %i is : %s\n", i, get_result->values.values_val [i].bamboo_value_val);
   }


 return 0;

}

*/
	
