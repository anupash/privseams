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
#include <openssl/sha.h>
#include <errno.h>
#include <signal.h>
#include "libhipopendht.h"
#include "libhipopendhtxml.h"
#include "debug.h"
#include "fcntl.h"
#include "ife.h"

/**
 *  For interrupting the connect in gethosts_hit 
 *  @param signo signal number
 *
 *  @return void
 */
static void 
connect_alarm(int signo)
{
    return; 
}

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
    else HIP_DEBUG("\nOpenDHT communication socket created successfully.\n");
    
    return(sockfd);      
}

/** 
 * resolve_dht_gateway_info - Resolves the gateway address
 * @param gateway_name FQDN of the gateway
 * @param gateway Addrinfo struct where the result will be stored
 *
 * @return Returns 0 on success otherwise -1
 */
int resolve_dht_gateway_info(char * gateway_name, 
                             struct addrinfo ** gateway){
    struct addrinfo hints;
    struct sockaddr_in *sa = NULL;
    int error;

    /*char *port_to_use = "5851";

    if(port != 0)
	port_to_use = itoa(port);*/

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NODHT;
    error = 0;
    
    error = getaddrinfo(gateway_name, "5851", &hints, gateway);
    if (error != 0){
        HIP_DEBUG("OpenDHT gateway resolving failed %s\n", gateway_name);
    }
    else{
	sa = (struct sockaddr_in *) (*gateway)->ai_addr;
	HIP_DEBUG("OpenDHT gateway IPv4: %s\n", inet_ntoa(sa->sin_addr));
    }
    
    return error;
}

/**
 *  connect_dht_gateway - Connects to given gateway
 *  @param sockfd
 *  @param addrinfo Address to connect to 
 *  @param blocking 1 for blocking connect 0 for nonblocking
 *
 *  @return Returns 0 on success -1 otherwise, if nonblocking can return EINPRGORESS
 */
int connect_dht_gateway(int sockfd, struct addrinfo * gateway, int blocking)
{
    int flags = 0, error = 0;
    struct sockaddr_in *sa;
    
    struct sigaction act, oact;
    act.sa_handler = connect_alarm;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    
    if (gateway == NULL) 
        {
            HIP_ERROR("No OpenDHT Serving Gateway Address.\n");
            return(-1);
        }
    
    if (blocking == 0)
        goto unblock;
    /* blocking connect */
    if (sigaction(SIGALRM, &act, &oact) <0 ) 
        {
            HIP_DEBUG("Signal error before OpenDHT connect, "
                      "connecting without alarm\n");
            error = connect(sockfd, gateway->ai_addr, gateway->ai_addrlen);
        }
    else 
        {
            HIP_DEBUG("Connecting to OpenDHT with alarm\n");
            if (alarm(4) != 0)
                HIP_DEBUG("Alarm was already set, connecting without\n");
            error = connect(sockfd, gateway->ai_addr, gateway->ai_addrlen);
            alarm(0);
            if (sigaction(SIGALRM, &oact, &act) <0 ) 
                HIP_DEBUG("Signal error after OpenDHT connect\n");
        }
    
    if (error < 0) 
        {
            HIP_PERROR("OpenDHT connect:");
            if (errno == EINTR)
                HIP_DEBUG("Connect to OpenDHT timedout\n");
            return(-1);
        }
    else
        {
            sa = (struct sockaddr_in *)gateway->ai_addr;
            HIP_DEBUG("Connected to OpenDHT gateway %s.\n", inet_ntoa(sa->sin_addr)); 
            return(0);
        }
        
 unblock:
    /* unblocking connect */    
    flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK); 
    
    sa = (struct sockaddr_in *)gateway->ai_addr;
    HIP_DEBUG("Connecting to OpenDHT gateway %s.\n", inet_ntoa(sa->sin_addr)); 
    
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

/** 
 * opendht_put_rm - Builds XML RPC packet and sends it through given socket and reads the response
 * @param sockfd Socket to be used with the send
 * @param key Key for the openDHT
 * @param value Value to be stored to the openDHT
 * @param secret Value to be used as a secret in remove
 * @param host Host address
 * @param response Buffer where the possible error message is saved 
 *
 * @return Returns integer -1 on error, on success 0
 */
int opendht_put_rm(int sockfd, 
                   unsigned char * key,
                   unsigned char * value, 
                   unsigned char * secret,
                   unsigned char * host,
                   int opendht_port,
                   int opendht_ttl)
{
    int key_len = 0;
    char put_packet[2048];
    char tmp_key[21];
    
    key_len = opendht_handle_key(key, tmp_key);
    
    /* Put operation FQDN->HIT */
    memset(put_packet, '\0', sizeof(put_packet));
    if (build_packet_put_rm((unsigned char *)tmp_key,
                         key_len,
                         (unsigned char *)value,
	                 strlen((char *)value),
                         (unsigned char *)secret,
                         strlen((char *)secret),
                         opendht_port,
                         (unsigned char *)host,
                         put_packet, opendht_ttl) != 0)
        {
            HIP_DEBUG("Put(rm) packet creation failed.\n");
            return(-1);
        }
    HIP_DEBUG("Host address in OpenDHT put(rm) : %s\n", host); 
    HIP_DEBUG("Actual OpenDHT send starts here\n");
    send(sockfd, put_packet, strlen(put_packet), 0);
    return(0);
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
    int value_len = 0;
    char put_packet[2048];
    char tmp_key[21];   
    char tmp_value[21];
        
    key_len = opendht_handle_key(key, tmp_key);   
    value_len = opendht_handle_value(value, tmp_value);
           
    /* Put operation FQDN->HIT */
    memset(put_packet, '\0', sizeof(put_packet));
    
    if (key_len > 0) {
            if (build_packet_put((unsigned char *)tmp_key,
                                 key_len,
                                 (unsigned char *)tmp_value,
                                 value_len,
                                 opendht_port,
                                 (unsigned char *)host,
                                 put_packet, opendht_ttl) != 0)
                    {
                            HIP_DEBUG("Put packet creation failed.\n");
                            return(-1);
                    }
    }  else {
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
    }
    HIP_DEBUG("Host address in OpenDHT put : %s\n", host); 
    HIP_DEBUG("Actual OpenDHT send starts here\n");
    send(sockfd, put_packet, strlen(put_packet), 0);
    return(0);
}

/** 
 * opendht_rm - Builds XML RPC packet and sends it through given socket and reads the response
 * @param sockfd Socket to be used with the send
 * @param key Key for the openDHT
 * @param value Value to be removed to the openDHT
 * @param secret Value to be used as a secret in remove
 * @param host Host address
 * @param response Buffer where the possible error message is saved 
 *
 * @return Returns integer -1 on error, on success 0
 */
int opendht_rm(int sockfd, 
                   unsigned char * key,
                   unsigned char * value, 
                   unsigned char * secret,
                   unsigned char * host,
                   int opendht_port,
                   int opendht_ttl)
{
    int key_len = 0;
    char put_packet[2048];
    char tmp_key[21];
    
    key_len = opendht_handle_key(key, tmp_key);
    
    /* Rm operation */
    memset(put_packet, '\0', sizeof(put_packet));
    if (build_packet_rm((unsigned char *)tmp_key,
                         key_len,
                         (unsigned char *)value,
	                 strlen((char *)value),
                         (unsigned char *)secret,
                         strlen((char *)secret),
                         opendht_port,
                         (unsigned char *)host,
                         put_packet, opendht_ttl) != 0)
        {
            HIP_DEBUG("Rm packet creation failed.\n");
            return(-1);
        }
    HIP_DEBUG("Host address in OpenDHT rm : %s\n", host); 
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

    key_len = opendht_handle_key(key, tmp_key);
    
    /* Get operation */
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
 * opendht_get_key - creates socket, connects to OpenDHT and gets the value under given key
 *
 * @param gateway A addrinfo struct containing the gateway address
 * @param key Pointer to key to be fetched
 * @param value Pointer to memory area where the corresponding value will be saved
 *
 * @return integer -1 on error, on success 0
 */
int opendht_get_key(struct addrinfo * gateway, const unsigned char * key,
		    unsigned char *value)
{
        int err = 0, sfd = -1, n_addrs = 0;
        int locator_item_count = 0;
        char dht_response[1400];
        char hostname[256];
        char *host_addr = NULL;
        struct hostent *hoste = NULL;
        struct hip_locator *locator;
        struct hip_locator_info_addr_item *locator_address_item = NULL;
        struct in6_addr addr6;
        struct in_addr addr4;
        
        memset(hostname,'\0',sizeof(hostname));
        HIP_IFEL((gethostname(hostname, sizeof(hostname))),-1,"Error getting hostname\n");
        HIP_IFEL(!(hoste = gethostbyname(hostname)),-1,
                 "Encountered an error when getting host address\n");
        if (hoste->h_addrtype == AF_INET)
                host_addr = inet_ntoa(*(struct in_addr *)*hoste->h_addr_list);
        else if (hoste->h_addrtype == AF_INET6) {
                HIP_IFEL(inet_ntop(AF_INET6, &hoste->h_addr_list, 
                                   host_addr, sizeof(INET6_ADDRSTRLEN)),
                         -1,"Error converting host IPv6 address\n");
        }
        else {
                HIP_DEBUG("Unknown host address family\n");
                goto out_err;
        }
        _HIP_DEBUG("Host addresss %s\n", host_addr);
        sfd = init_dht_gateway_socket(sfd);
        HIP_IFEL((err = connect_dht_gateway(sfd, gateway, 1))
                 ,-1,"OpenDHT connect error\n");  
        memset(dht_response, '\0', sizeof(dht_response));
        HIP_IFEL((err = opendht_get(sfd, (unsigned char *)key, (unsigned char *)host_addr, 5851)),
                 -1, "Opendht_get error");
        HIP_IFEL(opendht_read_response(sfd, dht_response), -1,"Opendht_read_response error\n"); 
        _HIP_DUMP_MSG((struct hip_common *)dht_response);
        /* check if there is locator, if is, take first and give it for the caller
           should give the whole locator and let the caller decide */
        locator = hip_get_param((struct hip_common *)dht_response, HIP_PARAM_LOCATOR);
        if (locator) {
                locator_item_count = hip_get_locator_addr_item_count(locator);
                locator_item_count--;
                locator_address_item = hip_get_locator_first_addr_item(locator);
                /*
                memcpy(&addr6, 
                       (struct in6_addr*)&locator_address_item[0].address, 
                       sizeof(struct in6_addr));
                */
                memcpy(&addr6, 
                       (struct in6_addr*)&locator_address_item[locator_item_count].address, 
                       sizeof(struct in6_addr));
                if (IN6_IS_ADDR_V4MAPPED(&addr6)) {
                        IPV6_TO_IPV4_MAP(&addr6, &addr4);
                        sprintf(value, "%s", inet_ntoa(addr4));
                } else {
                        hip_in6_ntop(&addr6, value);
                        HIP_DEBUG("Value: %s\n", value);
                }
        } else {
                if (ipv6_addr_is_hit((struct in6_addr*)dht_response)) {
                        /* if IPv6 must be HIT */
                        hip_in6_ntop((struct in6_addr *)dht_response, value);
                } else {
                        memcpy(value, dht_response, strlen(dht_response));
                }
        }
 out_err:
        if (sfd) close(sfd); 
        return(err);
}

/**
 * opendht_handle_value Modifies the key to suitable format for OpenDHT
 *
 * @param value Value to be handled
 * @param out_value Where the value will be saved
 *
 * @return larger than 0 if value was in IPv6 format (len of out_value)
 */
int opendht_handle_value(char * value, char * out_value) 
{
    int err = 0, value_len = 0;
    char tmp_value[21];
    struct in6_addr addrvalue;

    /* check for too long keys and convert HITs to numeric form */
    memset(tmp_value, '\0', sizeof(tmp_value));

    if (inet_pton(AF_INET6, (char *)value, &addrvalue.s6_addr) == 0)
        {
            /* inet_pton failed because of invalid IPv6 address */ 
        } 
    else 
        {
            /* value was in IPv6 format so propably is a HIT */
            memcpy(tmp_value, addrvalue.s6_addr, sizeof(addrvalue.s6_addr));
            value_len = sizeof(addrvalue.s6_addr);
            err = value_len;
            memcpy(out_value, tmp_value, sizeof(tmp_value));
        }
 out_err:
    return(err);
}

/**
 * opendht_handle_key Modifies the key to suitable format for OpenDHT
 *
 * @param key Key to be handled
 * @param out_key Where the key will be saved
 *
 * @return -1 if false otherwise it will be len of out_key
 */
int opendht_handle_key(char * key, char * out_key) 
{
    int err = 0, key_len = 0, i = 0 ;
    char tmp_key[21];
    struct in6_addr addrkey;
    unsigned char *sha_retval;

    /* check for too long keys and convert HITs to numeric form */
    memset(tmp_key, '\0', sizeof(tmp_key));

    if (inet_pton(AF_INET6, (char *)key, &addrkey.s6_addr) == 0)
        {
            /* inet_pton failed because of invalid IPv6 address */
            memset(tmp_key,'\0',sizeof(tmp_key));
            /* strlen works now but maybe not later */
            for (i = 0; i < strlen(key); i++ )
                    key[i] = tolower(key[i]);
            if (key[strlen(key)] == '.')
                key[strlen(key)] == '\0';
            sha_retval = SHA1(key, strlen(key), tmp_key); 
            key_len = 20;
            err = key_len;
            _HIP_HEXDUMP("KEY FOR OPENDHT", tmp_key, key_len);
            if (!sha_retval)
                {
                    HIP_DEBUG("SHA1 error when creating key for OpenDHT.\n");
                    return(-1);
                }                
        } 
    else 
        {
            /* key was in IPv6 format so propably is a HIT */
            memcpy(tmp_key, addrkey.s6_addr, sizeof(addrkey.s6_addr));
            key_len = sizeof(addrkey.s6_addr);
            err = key_len;
        }
    memcpy(out_key, tmp_key, sizeof(tmp_key));
 out_err:
    return(err);
}

/** 
 * opendht_read_response - Reads from the given socket and parses the XML RPC response
 * @param sockfd Socket to be used with the send
 * @param answer Buffer where the response value will be saved
 *
 * @return Returns integer, same as in read_packet_content
 * TODO: see read_packet_content
 */
int opendht_read_response(int sockfd, char * answer)
{
    int ret = 0, pton_ret = 0;
    int bytes_read;
    char read_buffer[2048];
    char tmp_buffer[2048];
    struct in_addr ipv4;
    struct in6_addr ipv6;

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

    /* If answer was IPv4 address mapped to IPv6 revert to IPv4 format*/
    pton_ret = inet_pton(AF_INET6, answer, &ipv6);

    if(IN6_IS_ADDR_V4MAPPED(&ipv6) && pton_ret)
        {
            IPV6_TO_IPV4_MAP(&ipv6, &ipv4);
            sprintf(answer, "%s", inet_ntoa(ipv4));
        }
    return(ret);
}

