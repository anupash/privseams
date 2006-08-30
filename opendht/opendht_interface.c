#include <stdio.h>
#include <stdlib.h> //a64
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "rpcif.h"
#include "opendht_interface.h"

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

  clnt = connectDHTserver();

  printf("Getting %s from DHT\n",hit);  

  memset (&get_args, 0, sizeof (get_args));
  
  sprintf(get_args.key,"%ld",a64l(hit));

  get_result = opendhtget(clnt, &get_args,10); // The 1 indicated the amount of results
  int j;
  //for(j=0;j<get_result->values.values_len;j++) //test line
  //   printf("results[%d]: %s\n",j,get_result->values.values_val[j].bamboo_value_val); //test line

  if (get_result->values.values_len == 0) {
    printf ("Key was not found from the openDHT (%s)\n", hit);
    return 1;
  }

  strncpy(res,get_result->values.values_val [0].bamboo_value_val, get_result->values.values_val [0].bamboo_value_len + 1);
  //printf("results: %s\n",get_result->values.values_val[0].bamboo_value_val); //test line
  return 0; //success

}

int opendhtgetbyhitmultiple(char *hit, char *ip, char *res)
{
  CLIENT *clnt;
  bamboo_get_args get_args;
  bamboo_get_res  *get_result;

  clnt = connectDHTserver();

  printf("Getting %s from DHT\n",hit);  

  memset (&get_args, 0, sizeof (get_args));
  
  sprintf(get_args.key,"%ld",a64l(hit));

  get_result = opendhtget(clnt, &get_args,10); // The 1 indicated the amount of results

  if (get_result->values.values_len == 0) 
     {
       printf("Key was not found from the openDHT (%s)\n", hit);
       return 1;
     }

  int j;
  for(j=0;j<get_result->values.values_len;j++) {
    if ( !strcmp(ip, get_result->values.values_val[j].bamboo_value_val) ) {
       printf("results[%d]: %s\n",j,get_result->values.values_val[j].bamboo_value_val); //test line
       strncpy(res,get_result->values.values_val [j].bamboo_value_val, get_result->values.values_val [0].bamboo_value_len + 1);
    }
  }

  //printf("results: %s\n",get_result->values.values_val[0].bamboo_value_val); //test line
  return 0; //success

}

int opendhtgetbyname(char *fqdn, char *res)
{
  int j;
  CLIENT *clnt;

  bamboo_get_args get_args;
  bamboo_get_res  *get_result;

  clnt = connectDHTserver();

  memset (&get_args, 0, sizeof (get_args));

  sprintf(get_args.key,"%ld",a64l(fqdn)); // Convert sha(fqdn) to binary
  
  get_result = opendhtget(clnt, &get_args,1); // The 1 indicated the amount of results
  
 if (get_result->values.values_len == 0) 
   {
     printf ("Get failed: returned %d values.\n", get_result->values.values_len);
     return 1;
   }
 strncpy(res,get_result->values.values_val [0].bamboo_value_val, get_result->values.values_val [0].bamboo_value_len);

 printf("Got %d results\n", get_result->values.values_len);
 //for(j=0;j<get_result->values.values_len;j++)
     //printf("results[%d]: %s\n",j,get_result->values.values_val[j].bamboo_value_val);

  return 0; //success
}

int opendhtputname(char *fqdn, char *hit)
{
  CLIENT *clnt;

  printf("Putting %s with hit %s\n",fqdn,hit);
  
  sprintf(fqdn,"%ld",a64l(fqdn));

  clnt = connectDHTserver();
  if(opendhtput(clnt,fqdn,hit,TTL))
    {
      printf("Could not put %s",hit);
      clnt_destroy (clnt);
      return 1;
    }
      printf("Putting %s with hit %s\n",fqdn,hit);
      clnt_destroy (clnt);
  return 0; //success
}

static void do_null_call (CLIENT *clnt) 
{
  char *null_args = NULL; 
  void *null_result; 
  printf ("Doing a null call.\n");
  null_result = bamboo_dht_proc_null_2((void*)&null_args, clnt);
  if (null_result == (void *) NULL) {
    clnt_perror (clnt, "null call failed.");
    exit (1);
  }
  printf ("Null call successful.\n");
}
  
static CLIENT* connectDHTserver(void)
{
  // host and port should be extracted from a file
  char host[] = "planetlab1.diku.dk";
  int port = 5852;

  CLIENT *clnt;
  struct sockaddr_in *addr = malloc(sizeof(struct sockaddr_in));
  struct hostent *h;
  int sockp = RPC_ANYSOCK; 
  
  //  printf("connecting to %s port %d\n",host, port);
  //Lookup server
    h = gethostbyname (host); 
  if (h == NULL) {
    printf("Could not resolve %s\n",host);
    clnt_destroy (clnt);
    exit(1);
  }
  //Create sockaddr_in
  bzero (addr, sizeof (struct sockaddr_in));
  addr->sin_family = AF_INET;
  addr->sin_port = htons (port);
  addr->sin_addr = *((struct in_addr *) h->h_addr);
  
  //Connect
  clnt = clnttcp_create (addr, BAMBOO_DHT_GATEWAY_PROGRAM, BAMBOO_DHT_GATEWAY_VERSION, &sockp, 0, 0);
  if (clnt == NULL) {
    clnt_pcreateerror ("Connect:");
    exit(1);
  }
  //  do_null_call(clnt);
  free(addr);
  return clnt;
}


int opendhtput(CLIENT* clnt, char* key, char* value, int ttl)
{
  bamboo_put_args put_args;
  bamboo_stat     *put_result;
  
  printf ("Doing a put\n key: %s val: %s ttl: %d\n",key, value,ttl);
    
  memset (&put_args, 0, sizeof (put_args));

  sprintf(put_args.key,"%ld",a64l(key));

  put_args.value.bamboo_value_val = value;
  put_args.value.bamboo_value_len = strlen (value);
  put_args.application = APP_STRING;
  put_args.client_library = CLIB_STRING;
  put_args.ttl_sec = ttl;

  put_result = bamboo_dht_proc_put_2 (&put_args, clnt);
  if (put_result == (bamboo_stat *) NULL) {
       clnt_perror (clnt, "put failed");
    exit (1);
  }  
    return 0;
}

int opendhtputhit(char *hit, char *ip)
{
  CLIENT *clnt;
  printf("Putting %s with ip %s\n",hit,ip);
  clnt = connectDHTserver();
  if(opendhtput(clnt,hit,ip,TTL))
    {
      printf("Could not put %s",hit);
      clnt_destroy (clnt);
      return 1;
    }
  clnt_destroy (clnt);
  return 0; //success
}

  
static bamboo_get_res* opendhtget(CLIENT* clnt, bamboo_get_args *get_args, int maxvals)
{
  bamboo_get_res  *get_result;
  printf ("Doing a get\n");

  get_args->application = APP_STRING;
  get_args->client_library = CLIB_STRING;
  get_args->maxvals = maxvals;

  get_result = bamboo_dht_proc_get_2 (get_args, clnt);
  if (get_result == (bamboo_get_res *) NULL) {
    clnt_perror (clnt, "get failed");
    exit (1);
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
	
