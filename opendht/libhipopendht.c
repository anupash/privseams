/* opendht_xml_interface.c supports put/get XML RPC interface */
/* NOTE: you must use port 5851 because openDHT accepts XML RPC only on that port */
/* TODO: support for put_removable and rm */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <errno.h>
#include "libhipopendht.h"
#include "libhipopendhtxml.h"
#include "debug.h"
#include "time.h"

struct timeval opendht_timer_before, opendht_timer_after;
unsigned long opendht_timer_diff_sec, opendht_timer_diff_usec;

/** 
 * resolve_dht_gateway_info - Resolves the gateway address
 * @param gateway FQDN of the gateway
 * @param sock_family Desired protocol family
 *
 * @return Returns 0 on success otherwise -1
 */
int resolve_dht_gateway_info(char * gateway, sa_family_t sock_family)
{
    struct addrinfo hints, *res;
    int s, error;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = sock_family;
    hints.ai_socktype = SOCK_STREAM;

    error = getaddrinfo(gateway, "5851", &hints, &res);
    if (error != 0) 
    {
        printf("Could NOT resolve %s\n", gateway);
        return(-1);
    }

    s = -1;   
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) 
        perror("Socket");
    else
    {
        //HIP_START_TIMER(opendht_timer); /* For testing */
        gettimeofday(&opendht_timer_before, NULL);
        if (connect(s, res->ai_addr, res->ai_addrlen) < 0) 
        {
            perror("Connect");
            s = -1;
        }
        else
	{
	  /* printf("Connected to gateway.\n"); */  /* test line */
        }
    }

    if (s < 0)  printf("Resolving and connecting failed.\n");
    freeaddrinfo(res);
    return(s);
}

/** 
 * opendht_put_b - Builds XML RPC packet and sends it through given socket and reads the response
 * @param sockfd Socket to be used with the send
 * @param key Key for the openDHT
 * @param value Value to be stored to the openDHT
 * @param host Host address
 * @param response Buffer where the possible error message is saved 
 *
 * @return Returns integer -1 on error, on success 0
 */
int opendht_put_b(int sockfd, 
                  unsigned char * key,
                  unsigned char * value, 
                  unsigned char * host, 
                  char * response)
{
    int r = 0;
    int key_len = 0;
    int dht_port = 5851;
    char put_packet[2048];
    char answer[1024];
    char tmp_key[21];
    struct in6_addr addrkey;

    /* check for too long keys and convert HITs to numeric form */
    memset(tmp_key, '\0', sizeof(tmp_key));
    if (inet_pton(AF_INET6, (char *)key, &addrkey.s6_addr) == 0)
    {
        /* inet_pton failed because of invalid IPv6 address */
        if (strlen((char *)key) > 20)
        {
            strncpy(tmp_key, (char *)key, 20);
            key_len = strlen(tmp_key);
        }
        else
        {
            strcpy(tmp_key, (char *)key);
            key_len = strlen(tmp_key);
        }
    } 
    else 
    {
        /* key was in IPv6 format so propably is a HIT */
        memcpy(tmp_key, addrkey.s6_addr, sizeof(addrkey.s6_addr));
        key_len = sizeof(addrkey.s6_addr);
    }

    /* Put operation FQDN->HIT */
    memset(put_packet, '\0', sizeof(put_packet));
    if (build_packet_put((unsigned char *)tmp_key,
                         key_len,
                         (unsigned char *)value,
	                 strlen((char *)value),
                         dht_port,
                         (unsigned char *)host,
                         put_packet) != 0)
    {
        HIP_DEBUG("Put packet creation failed.\n");
        return(-1);
    }
    
    send(sockfd, put_packet, strlen(put_packet), 0);
 
    r = opendht_read_response_b(sockfd, answer);
    if (r == 0)
        memcpy(response, answer, sizeof(answer)); 
    else 
        response[0] = '\0';

    return(r);
}

/** 
 * opendht_get_b - Builds XML RPC packet and sends it through given socket and reads the response
 * @param sockfd Socket to be used with the send
 * @param key Key for the openDHT
 * @param value Value to be stored to the openDHT
 * @param host Host address
 * @param response Buffer where the possible error message is saved 
 *
 * @return Returns integer -1 on error, on success 0
 */
int opendht_get_b(int sockfd, 
                  unsigned char * key, 
                  unsigned char * host,
                  char * response)
{
    int r = 0;
    int key_len = 0;
    int dht_port = 5851;
    char get_packet[2048];
    char answer[1024];
    char tmp_key[21];
    struct in6_addr addrkey;

    /* check for too long keys and convert HITs to numeric form */
    memset(tmp_key, '\0', sizeof(tmp_key));
    if (inet_pton(AF_INET6, (char *)key, &addrkey.s6_addr) == 0)
    {
        /* inet_pton failed because of invalid IPv6 address */
        if (strlen((char *)key) > 20)
        {
            strncpy(tmp_key, (char *)key, 20);
            key_len = strlen(tmp_key);
        }
        else
        {
            strcpy(tmp_key, (char *)key);
            key_len = strlen(tmp_key);
        }
    }
    else 
    {
        /* key was in IPv6 format so propably is a HIT */
        memcpy(tmp_key, addrkey.s6_addr, sizeof(addrkey.s6_addr));
        key_len = sizeof(addrkey.s6_addr);
    }

    /* Put operation FQDN->HIT */
    memset(get_packet, '\0', sizeof(get_packet));
    if (build_packet_get((unsigned char *)tmp_key,
                         key_len,
                         dht_port,
                         (unsigned char *)host,
                         get_packet) !=0)
    {
        HIP_DEBUG("Get packet creation failed.\n");  
        return(-1);
    }
  
    send(sockfd, get_packet, strlen(get_packet), 0);
    r = opendht_read_response_b(sockfd, answer); 
    memcpy(response, answer, sizeof(answer));
 
    return(r);

}
/** 
 * opendht_read_respoonse_b - Reads from the given socket and parses the XML RPC response
 * @param sockfd Socket to be used with the send
 * @param answer Buffer where the response value will be saved
 *
 * @return Returns integer, same as in read_packet_content
 * TODO: see read_packet_content
 */
int opendht_read_response_b(int sockfd, char * answer)
{
    int ret = 0;
    int bytes_read;
    char read_buffer[2048];
    char tmp_buffer[2048];

    memset(read_buffer, '\0', sizeof(read_buffer));
    do
    {
        memset(tmp_buffer, '\0', sizeof(tmp_buffer));
        bytes_read = recv(sockfd, tmp_buffer, sizeof(tmp_buffer), 0);
        if (bytes_read > 0)
            memcpy(&read_buffer[strlen(read_buffer)], tmp_buffer, sizeof(tmp_buffer));
    }
    while (bytes_read > 0);

    //HIP_STOP_TIMER(opendht_timer, "OpenDHT get/put connection"); /* For testing */
    gettimeofday(&opendht_timer_after, NULL);    
    opendht_timer_diff_sec  = (opendht_timer_after.tv_sec - opendht_timer_before.tv_sec) * 1000000;
    opendht_timer_diff_usec = opendht_timer_after.tv_usec - opendht_timer_before.tv_usec;
    HIP_INFO("OpenDHT connect took %.3f sec\n",
             (opendht_timer_diff_sec+opendht_timer_diff_usec) / 1000000.0);


    /* Parse answer */
    memset(answer, '\0', sizeof(answer));
    ret = 0;
    ret = read_packet_content(read_buffer, answer); 
    return(ret);
}

/** 
 * print_explanation - Prints explanation of the parsers return values, JUST for test purposes
 * TO BE REMOVED
 * @param return_code Integer returned by read_packet_content
 */
void print_explanation(int return_code)
{
    if (return_code == -2)
        printf("Error in XML content.\n");
    if (return_code == -1)
        printf("Error: Didn't receive HTTP header/XML payload\n");
    if (return_code == 0)
        printf("Put was succesfull\n");
    if (return_code == 1)
        printf("Put failed: over capacity.\n");
    if (return_code == 2)
        printf("Put failed: try again\n");
    if (return_code == 3)
        printf("Received (a) value(s)\n");
}
