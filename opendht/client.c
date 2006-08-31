#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "rpcif.h"

#define APP_STRING "OpenDHT HIP Interface $Revision: 1.2 $"
#define CLIB_STRING "rpcgen"

static void 
do_null_call (CLIENT *clnt) {
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
  
static CLIENT* connectDHTserver(char *host, int port)
{
  CLIENT *clnt;
    struct sockaddr_in *addr = malloc(sizeof(struct sockaddr_in));
    struct hostent *h;
    int sockp = RPC_ANYSOCK; 
    char *null_args = NULL; 
    void *null_result; 

    printf("connecting to %s port %d\n",host, port);
   //Lookup server
    h = gethostbyname (host); 
    if (h == NULL) {
      printf("Could not resolve %s\n",host);
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

    do_null_call(clnt);
    free(addr);
    return clnt;
}




int opendhtput(CLIENT* clnt, char* key, char* value, int ttl)
{
   
  bamboo_put_args put_args;
  bamboo_stat     *put_result;
  
  printf ("Doing a put\n key: %s val: %s ttl: %d\n",key, value,ttl);
    
  memset (&put_args, 0, sizeof (put_args));
  strcpy(put_args.key,key);
  put_args.value.bamboo_value_val = value;
  put_args.value.bamboo_value_len = sizeof (value);
  put_args.application = APP_STRING;
  put_args.client_library = CLIB_STRING;
  put_args.ttl_sec = ttl; 

  put_result = bamboo_dht_proc_put_2 (&put_args, clnt);
  if (put_result == (bamboo_stat *) NULL) {
    clnt_perror (clnt, "put failed");
    exit (1);
  }
  
  printf ("Put successful\n");
  
    return 0;
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

 clnt = connectDHTserver(host,port);
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

