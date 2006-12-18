/* Teststub for the openDHT interface  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <errno.h>
#include "libhipopendht.h"
#include "debug.h"

int main(int argc, char *argv[])
{
    int s, ret, error;
    /*
    struct in6_addr val_hit_addr;
    struct in6_addr val_ip_addr;
    char opendht[] = "opendht.nyuld.net";
    */
    char opendht[] = "planetlab1.diku.dk";
    char dht_response[1024];
    char dht_response2[1024];

    /* Test values */  
    char val_bogus[] = "BogusKey";
    char val_host[] = "testhostname";
    char val_hit[] = "2001:0071:7c97:a5b4:6c73:1b1b:081e:126d";
    char val_ip[] = "128.196.1.100";
    char host_addr[] = "127.0.0.1"; /* TODO change this to something smarter :) */

    /*
    if ((ret = inet_pton(AF_INET6, val_hit, &val_hit_addr)) != 1)
    {
        printf("Could not create test in6_addr struct for hit.\n");
        exit(1);
    }
    if ((ret = inet_pton(AF_INET, val_ip, &val_ip_addr)) != 1)
    {
        printf("Could not create test in6_addr struct for ip.\n");
        exit(1);
    }
    */

    printf("Starting to test the openDHT interface.\n");
    printf("Using test mapping\n'%s (FQDN) -> %s (HIT) -> %s (IP)'.\n",
           val_host, val_hit, val_ip);
  
    /*!!!! put fqdn->hit !!!!*/
    s = init_dht_gateway_socket(s);
    error = resolve_dht_gateway_info (opendht, s);
    if (error < 0) exit(0);
    ret = 0;
    ret = opendht_put(s, (unsigned char *)val_host,
                        (unsigned char *)val_hit, (unsigned char *)host_addr);   
    ret = opendht_read_response(s, dht_response); 
    if (ret == -1) exit(1);
    printf("Put packet (fqdn->hit) sent and ...\n");
    printf("Put was success\n");
    close(s);

    /*!!!! put hit->ip !!!!*/  
    s = init_dht_gateway_socket(s);
    error = resolve_dht_gateway_info (opendht, s);
    if (error < 0) exit(0);
    ret = 0;
    ret = opendht_put(s, (unsigned char *)val_hit,
                        (unsigned char *)val_ip, (unsigned char *)host_addr);
    ret = opendht_read_response(s, dht_response); 
    if (ret == -1) exit(1);
    printf("Put packet (hit->ip) sent and ...\n");
    printf("Put was success\n", dht_response);
    close(s);

    /*!!!! get fqdn !!!!*/
    s = init_dht_gateway_socket(s);
    error = resolve_dht_gateway_info (opendht, s);
    if (error < 0) exit(0);
    ret = 0;
    memset(dht_response, '\0', sizeof(dht_response));
    ret = opendht_get(s, (unsigned char *)val_host, (unsigned char *)host_addr);
    ret = opendht_read_response(s, dht_response); 
    if (ret == -1) exit (1);
    printf("Get packet (fqdn) sent and ...\n");
    if (ret == 0) 
    {
        printf("Value received from DHT: %s\n", dht_response);
        if (!strcmp(dht_response, val_hit)) 
            printf("Did match the sent value.\n");
        else
            printf("Did NOT match the sent value!\n");
    }
    close(s);

    /*!!!! get hit !!!!*/
    s = init_dht_gateway_socket(s);
    error = resolve_dht_gateway_info (opendht, s);
    if (error < 0) exit(0);
    ret = 0;
    memset(dht_response2, '\0', sizeof(dht_response2));
    ret = opendht_get(s, (unsigned char *)val_hit, (unsigned char *)host_addr); 
    ret = opendht_read_response(s, dht_response2); 
    if (ret == -1) exit (1);
    printf("Get packet (hit) sent and ...\n");
    if (ret == 0)
    {
        printf("Value received from DHT: %s\n",dht_response2);
        if (!strcmp(dht_response2, val_ip))
            printf("Did match the sent value.\n");
        else
            printf("Did NOT match the sent value!\n");
    }
    close(s);

    /* Finally let's try to get a key that doesn't exist */
    s = init_dht_gateway_socket(s);
    error = resolve_dht_gateway_info (opendht, s);
    if (error < 0) exit(0);
    ret = 0;
    memset(dht_response2, '\0', sizeof(dht_response2));
    ret = opendht_get(s, (unsigned char *)val_bogus, (unsigned char *)host_addr); 
    ret = opendht_read_response(s, dht_response2); 
    if (ret == -1) exit (1);
    printf("Get packet (bogus, will not be found (hopefully)) sent and ...\n");
    printf("Value received from DHT: %s\n",dht_response2);   
    close(s);
    exit(EXIT_SUCCESS);
}
