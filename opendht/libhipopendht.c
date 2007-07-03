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
#include "fcntl.h"


/*
#include "time.h"

struct timeval opendht_timer_before, opendht_timer_after;
unsigned long opendht_timer_diff_sec, opendht_timer_diff_usec;
*/

/**
 * init_dht_gateway_socket - Initializes socket for the openDHT communications
 * @param sockfd Socket descriptor to be initialized.
 *
 * @return Returns positive if socket creation was ok negative on error.
 */
int init_dht_gateway_socket(int sockfd)
{
    if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        HIP_PERROR("OpenDHT socket:");
   else HIP_DEBUG("\n OpenDHT communication socket created successfully \n");

    return(sockfd);      
}

/** 
 * resolve_dht_gateway_info - Resolves the gateway address
 * @param gateway_name FQDN of the gateway
 * @param gateway Addrinfo struct here the result will be stored
 *
 * @return Returns 0 on success otherwise -1
 */
int resolve_dht_gateway_info(char * gateway_name, 
                             struct addrinfo * gateway)
{
	struct addrinfo hints, *res;
	int error;
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NODHT;
	error = 0;
	
	error = getaddrinfo(gateway_name, "5851", &hints, &res);
	//error = getaddrinfo(gateway_name, NULL, &hints, &res);
	if (error != 0)
		HIP_DEBUG("OpenDHT gateway resolving failed\n");
	else
	{
		memcpy(gateway, res, sizeof(struct addrinfo));
		struct sockaddr_in *sa = (struct sockaddr_in *) gateway->ai_addr;
		HIP_DEBUG("OpenDHT gateway IPv4/ %s\n", inet_ntoa(sa->sin_addr));
	}
	
	if (res) freeaddrinfo(res);
	return error;
}

/**
 *  connect_dht_gateway - Connects to given gateway
 *  @param sockfd
 *  @param addrinfo Address to connect to 
 *  @param blocking 1 for blocking connect 0 for nonblocking
 *
 *  @return Returns 0 on success -1 otherwise, if nonblocking can return also EINPRGORESS
 */
int connect_dht_gateway(int sockfd, struct addrinfo * gateway, int blocking)
{
    int flags = 0;
    struct sockaddr_in *sa;

    if (blocking == 1)
      {
        if (connect(sockfd, gateway->ai_addr, gateway->ai_addrlen) < 0) 
          {
            HIP_PERROR("OpenDHT connect:");
            return(-1);
          }
        else
          {
            sa = (struct sockaddr_in *)gateway->ai_addr;
            HIP_DEBUG("Connected to OpenDHT gateway %s.\n", inet_ntoa(sa->sin_addr)); 
            return(0);
          }
      }
    else
      {
            flags = fcntl(sockfd, F_GETFL, 0);
            fcntl(sockfd, F_SETFL, flags | O_NONBLOCK); 
            if (connect(sockfd, gateway->ai_addr, gateway->ai_addrlen) < 0)
              {
                if (errno == EINPROGRESS)
                  return(EINPROGRESS);
                else 
                  {
                    HIP_PERROR("OpenDHT connect:");
                    return(-1);
                  }
              }
            else
              {
                /* connect ok */
                return(0);
              }

      }

} 

/** 
 * opendht_put - Builds XML RPC packet and sends it through given socket and reads the response
 * @param sockfd Socket to be used with the send
 * @param key Key for the openDHT
 * @param value Value to be stored to the openDHT
 * @param host Host address
 * @param response Buffer where the possible error message is saved 
 *
 * @return Returns integer -1 on error, on success 0
 */
int opendht_put(int sockfd, 
                unsigned char * key,
                unsigned char * value, 
                unsigned char * host,
                int opendht_port,
                int opendht_ttl)
{
    int key_len = 0;
    char put_packet[2048];
    char tmp_key[21];
    struct in6_addr addrkey;
    //    int opendht_ttl = 120;
    //int opendht_port = 5851;

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
                         opendht_port,
                         (unsigned char *)host,
                         put_packet, opendht_ttl) != 0)
    {
        HIP_DEBUG("Put packet creation failed.\n");
        return(-1);
    }
    HIP_DEBUG("Host address in OpenDHT put : %s\n", host); 
    HIP_DEBUG("Actual OpenDHT send starts here\n");
    send(sockfd, put_packet, strlen(put_packet), 0);
    return(0);
}

/** 
 * opendht_get - Builds XML RPC packet and sends it through given socket and reads the response
 * @param sockfd Socket to be used with the send
 * @param key Key for the openDHT
 * @param value Value to be stored to the openDHT
 * @param host Host address
 * @param response Buffer where the possible error message is saved 
 *
 * @return Returns integer -1 on error, on success 0
 */
int opendht_get(int sockfd, 
                unsigned char * key, 
                unsigned char * host,
                int port)
{
    int key_len = 0;
    char get_packet[2048];
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
                         port,
                         (unsigned char *)host,
                         get_packet) !=0)
    {
        HIP_DEBUG("Get packet creation failed.\n");  
        return(-1);
    }
  
    send(sockfd, get_packet, strlen(get_packet), 0);
    return(0);
}
/** 
 * opendht_read_respoonse - Reads from the given socket and parses the XML RPC response
 * @param sockfd Socket to be used with the send
 * @param answer Buffer where the response value will be saved
 *
 * @return Returns integer, same as in read_packet_content
 * TODO: see read_packet_content
 */
int opendht_read_response(int sockfd, char * answer)
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

    /* Parse answer */
    memset(answer, '\0', sizeof(answer));
    ret = 0;
    ret = read_packet_content(read_buffer, answer); 
    return(ret);
}

