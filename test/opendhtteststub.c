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
    if (argc != 3) {
        printf("Usage: %s num iterations\n", argv[0]);
        printf("Num = 0 for regular testing of functions "
               "(iterations not used just give 1)\n"
               "Num = 1 get test times when value not found\n"
               "Num = 2 get test times when value is found\n"
               "Num = 3 put test times with 10 byte value (same key)\n"
               "Num = 4 put test times with 10 byte value, "
               "waiting 5 sec in between puts(same key)\n"
               "Num = 5 put test times with 10 byte value (random key, short TTL)\n"
               "Num = 6 put test times with 10 byte value, waiting 5 sec "
               "in between puts(random key, short TTL)\n"
               "Num = 7 put test times with consecutive keys and 985 byte values\n"
               "Num = 8 put test times with consecutive keys and 985 byte values "
               "with 5 sec sleep in between puts\n"
               "Num = 9 get test times with consecutive keys (do number 7 or 8 first)\n"
               "Num = 'a' remove testing\n"
               "Iterations, just as it says\n"
               "Connect errors will print 999;999\n");
        exit(EXIT_SUCCESS);
    }

    int s, ret, error;
    int ttl = 60;
    /*
    struct in6_addr val_hit_addr;
    struct in6_addr val_ip_addr; 
    */
    char opendht[] = "opendht.nyuld.net";
    /* both responses were 1024 before */
    /* now more because base64 lengthens the message */
    char dht_response[1400]; 
    char dht_response2[1400]; 
    /* Test values */  
    char val_bogus[] = "BogusKey";
    char val_host[] = "testhostname";
    char val_hosti[] = "testhostname2";
    char val_host_test[] = "hosttestname2";
    char val_something[] = "hi-to-everyone";
    char secret_str[] = "secret_str_is_secret";
    char key_test[] = "Testiavain"; 
    char key_rand[] = "random_key";
    char val_tenbyte[] = "1234567890";
    /* smaller than 1K actually because any larger will bounce from DHT */
    char val_onekilo[985]; 
    char val_hit[] = "2001:0071:7c97:a5b4:6c73:1b1b:081e:126d";
    char val_ip[] = "128.196.1.100";
    /* TODO change this to something smarter :) */
    char host_addr[] = "127.0.0.1"; 
    int n = 0, iter = 0;
    struct timeval conn_before, conn_after; 
    struct timeval stat_before, stat_after;
    struct timeval put_rm_before, put_rm_after;
    struct timeval put_rm2_before, put_rm2_after;
    struct timeval rm_before, rm_after;
    unsigned long conn_diff_sec, conn_diff_usec;
    unsigned long stat_diff_sec, stat_diff_usec;
    unsigned long put_rm_diff_sec, put_rm_diff_usec;
    unsigned long put_rm2_diff_sec, put_rm2_diff_usec;
    unsigned long rm_diff_sec, rm_diff_usec;
    iter = atoi(argv[2]);
    struct addrinfo * serving_gateway;

    /* resolve the gateway address */
    error = resolve_dht_gateway_info (opendht, &serving_gateway);
    if (error < 0) {
        printf("Resolving error\n");
        exit(0);
    }

    if (argv[1][0] == '0') 
        {
            printf("Starting to test the openDHT interface.\n");
            printf("Using test mapping\n'%s (FQDN) -> %s (HIT) -> %s (IP)'.\n",
                   val_host, val_hit, val_ip);
            
            /*!!!! put fqdn->hit !!!!*/
            s = init_dht_gateway_socket(s);
            error = 0;
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            ret = opendht_put(s, 
                              (unsigned char *)val_host,
                              (unsigned char *)val_hit, 
                              (unsigned char *)host_addr,5851,ttl);   
            ret = opendht_read_response(s, dht_response); 
            if (ret == -1) exit(1);
            printf("Put packet (fqdn->hit) sent and ...\n");
            printf("Put was success\n");
            close(s);
            /*!!!! put hit->ip !!!!*/ 
            
            s = init_dht_gateway_socket(s);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            ret = opendht_put(s, 
                              (unsigned char *)val_hit,
                              (unsigned char *)val_ip, 
                              (unsigned char *)host_addr,5851,ttl);
            ret = opendht_read_response(s, dht_response); 
            if (ret == -1) exit(1);
            printf("Put packet (hit->ip) sent and ...\n");
            printf("Put was success\n", dht_response);
            close(s);
            
            /*!!!! get fqdn !!!!*/
            
            s = init_dht_gateway_socket(s);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            memset(dht_response, '\0', sizeof(dht_response));
            ret = opendht_get(s, (unsigned char *)val_host, (unsigned char *)host_addr, 5851);
            ret = opendht_read_response(s, dht_response); 
            // if (ret == -1) exit (1);
            printf("Get packet (fqdn) sent and ...\n");
            if (ret == 0) 
                {
                    printf("Teststub: Value received from DHT: %s\n", dht_response);
                    if (!strcmp(dht_response, val_hit)) 
                        printf("Did match the sent value.\n");
                    else
                        printf("Did NOT match the sent value!\n");
                }
            close(s);
            
            /*!!!! get hit !!!!*/
   
            s = init_dht_gateway_socket(s);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            memset(dht_response2, '\0', sizeof(dht_response2));
            ret = opendht_get(s, (unsigned char *)val_hit, (unsigned char *)host_addr, 5851); 
            ret = opendht_read_response(s, dht_response2); 
            if (ret == -1) exit (1);
            printf("Get packet (hit) sent and ...\n");
            if (ret == 0)
                {
                    printf("Teststub: Value received from DHT: %s\n",dht_response2);
                    if (!strcmp(dht_response2, val_ip))
                        printf("Did match the sent value.\n");
                    else
                        printf("Did NOT match the sent value!\n");
                }
            close(s);
            
            /* Finally let's try to get a key that doesn't exist */
            
            s = init_dht_gateway_socket(s);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            memset(dht_response2, '\0', sizeof(dht_response2));
            ret = opendht_get(s, (unsigned char *)val_bogus, (unsigned char *)host_addr, 5851); 
            ret = opendht_read_response(s, dht_response2); 
            // if (ret == -1) exit (1);
            printf("Get packet (bogus, will not be found (hopefully)) sent and ...\n");
            printf("Teststub: Value received from DHT: %s\n",dht_response2);   
            close(s);

            /* put_removable and rm tests */
      
            /* put_removable */
            HIP_DEBUG("\n\nPut removable starts\n");
            s = init_dht_gateway_socket(s);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            memset(dht_response2, '\0', sizeof(dht_response2));
            ret = opendht_put_rm(s, 
                                 (unsigned char *)val_host_test,
                                 (unsigned char *)val_something,
                                 (unsigned char *)secret_str,
                                 (unsigned char *)host_addr,5851,ttl);   
            ret = opendht_read_response(s, dht_response2); 
            if (ret == -1) exit(1);
            printf("Put(rm) packet (fqdn->hit) sent and ...\n");
            printf("Put(rm) was success\n");
            close(s);
            /* check that value exists */
            s = init_dht_gateway_socket(s);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            memset(dht_response2, '\0', sizeof(dht_response2));
            ret = opendht_get(s, (unsigned char *)val_host_test, 
                              (unsigned char *)host_addr, 5851); 
            ret = opendht_read_response(s, dht_response2); 
            // if (ret == -1) exit (1);
            printf("Get packet sent and (value should be found, just sent it)...\n");
            printf("Value received from DHT: %s\n",dht_response2);   
            close(s);
            /* send remove */
            s = init_dht_gateway_socket(s);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            memset(dht_response2, '\0', sizeof(dht_response2));
            ret = opendht_rm(s, 
                                 (unsigned char *)val_host_test,
                                 (unsigned char *)val_something,
                                 (unsigned char *)secret_str,
                                 (unsigned char *)host_addr,5851,ttl);   
            ret = opendht_read_response(s, dht_response2); 
            if (ret == -1) exit(1);
            printf("Rm packet sent and ...\n");
            printf("Rm was success\n");
            close(s);
            /* can you get it anymore */
      
            s = init_dht_gateway_socket(s);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            memset(dht_response2, '\0', sizeof(dht_response2));
            ret = opendht_get(s, (unsigned char *)val_host_test, 
                              (unsigned char *)host_addr, 5851); 
            ret = opendht_read_response(s, dht_response2); 
            // if (ret == -1) exit (1);
            printf("Get packet (was removed, will not be found (hopefully)) sent and ...\n");
            printf("Teststub: Value received from DHT: %s\n",dht_response2);   
            close(s);
            
            /* testing a wrapper for blocking dht call */
            memset(dht_response, '\0', sizeof(dht_response));
            ret = 0;
            HIP_DEBUG("\n\nTrying out get wrapper\n");
            ret = opendht_get_key(serving_gateway, val_hit, dht_response);

            if (!ret)
                HIP_DEBUG("DHT get succeeded\n");
            else
                HIP_DEBUG("DHT get was unsuccesfull\n");
            
            /* basic testing done */
            exit(EXIT_SUCCESS);
        }
    else if (argv[1][0] == '1') 
        {            
            printf("Get test times when value not found\n");
            printf("Printing \"connection time; get time; DHT answer (should be empty here)\n");
            printf("Doing %s iterations\n", argv[2]);
            
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    s = init_dht_gateway_socket(s);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999;999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            gettimeofday(&stat_before, NULL);
                            ret = opendht_get(s, (unsigned char *)val_bogus, 
                                              (unsigned char *)host_addr, 5851); 
                            ret = opendht_read_response(s, dht_response2); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f;%.6f;%s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response2);
                        }
                }
        }
    else if (argv[1][0] == '2')
        {
            printf("Get test times when value is found\n");
            printf("Printing \"connection time; get time; DHT answer "
                   "(0 = OK, 1 = error, 2 = retry, or some value)\n");
            printf("Doing %s iterations\n", argv[2]);
            
            s = init_dht_gateway_socket(s);
            error = connect_dht_gateway(s, serving_gateway, 1);
            if (error < 0) exit(0);
            ret = 0;
            /* iterations by estimate seconds, so the value is there long enough */
            ret = opendht_put(s, (unsigned char *)val_hit,
                              (unsigned char *)val_ip, 
                              (unsigned char *)host_addr,5851,(iter * 3)); 
            ret = opendht_read_response(s, dht_response); 
            if (ret == -1) exit(1);
            printf("Put packet (hit->ip) sent and ...\n");
            printf("Put was success\n", dht_response);
            close(s);

            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    s = init_dht_gateway_socket(s);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999;999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            gettimeofday(&stat_before, NULL);
                            ret = opendht_get(s, (unsigned char *)val_hit, 
                                              (unsigned char *)host_addr, 5851); 
                            ret = opendht_read_response(s, dht_response2); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f;%.6f;%s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response2);
                        }
                }
        }
    else if (argv[1][0] == '3')
        {
            printf("Put test times with 10 byte value (same key)\n");
            printf("Printing \"connection time; get time; DHT answer "
                   "(0 = OK, 1 = error, 2 = retry, or some value)\n");
            printf("Doing %s iterations\n", argv[2]);
            
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    s = init_dht_gateway_socket(s);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999;999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            gettimeofday(&stat_before, NULL);
                            /* TTL just 20 secs */
                            ret = opendht_put(s, (unsigned char *)key_test,
                                              (unsigned char *)val_tenbyte, 
                                              (unsigned char *)host_addr,5851,20); 
                            ret = opendht_read_response(s, dht_response); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f;%.6f;%s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response);
                        }
                }
        }
    else if (argv[1][0] == '4')
        {
            printf("Put test times with 10 byte value, waiting "
                   "5 sec in between puts (same key)\n");
            printf("Printing \"connection time; get time; DHT answer "
                   "(0 = OK, 1 = error, 2 = retry, or some value)\n");
            printf("Doing %s iterations\n", argv[2]);
            
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    s = init_dht_gateway_socket(s);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999;999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            gettimeofday(&stat_before, NULL);
                            /* TTL just 20 secs */
                            ret = opendht_put(s, (unsigned char *)key_test,
                                              (unsigned char *)val_tenbyte, 
                                              (unsigned char *)host_addr,5851,20); 
                            ret = opendht_read_response(s, dht_response); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f;%.6f;%s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response);
                            sleep(5);
                        }
                }
        }
    else if (argv[1][0] == '5')
        {
            printf("Put test times with 10 byte value (random key, short TTL)\n");
            printf("Printing \"connection time; get time; DHT answer "
                   "(0 = OK, 1 = error, 2 = retry, or some value)\n");
            printf("Doing %s iterations\n", argv[2]);

            srand(time(NULL));
            int ra = 0;
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    ra= rand() % 1000000000;
                    sprintf(key_rand, "%.d", ra);
                    HIP_DEBUG("random key  %s\n", key_rand);
                    s = init_dht_gateway_socket(s);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999;999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            gettimeofday(&stat_before, NULL);
                            /* TTL just 20 secs */
                            ret = opendht_put(s, (unsigned char *)key_rand,
                                              (unsigned char *)val_tenbyte, 
                                              (unsigned char *)host_addr,5851,20); 
                            ret = opendht_read_response(s, dht_response); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f;%.6f;%s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response);
                        }
                }
        }
    else if (argv[1][0] == '6')
        {
            printf("Put test times with 10 byte value, waiting 5 sec in "
                   "between puts(random key, short TTL)\n");
            printf("Printing \"connection time; get time; DHT answer "
                   "(0 = OK, 1 = error, 2 = retry, or some value)\n");
            printf("Doing %s iterations\n", argv[2]);
            srand(time(NULL));
            int ra = 0;
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    ra= rand() % 1000000000;
                    sprintf(key_rand, "%.d", ra);
                    HIP_DEBUG("random key  %s\n", key_rand);
                    s = init_dht_gateway_socket(s);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999;999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            gettimeofday(&stat_before, NULL);
                            /* TTL just 20 secs */
                            ret = opendht_put(s, (unsigned char *)key_rand,
                                              (unsigned char *)val_tenbyte, 
                                              (unsigned char *)host_addr,5851,20); 
                            ret = opendht_read_response(s, dht_response); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f;%.6f;%s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response);
                            sleep(5);
                        }
                }
        }
    else if (argv[1][0] == '7')
        {
            memset(val_onekilo,'a',sizeof(val_onekilo));
            printf("Put test times with consecutive keys and 985 byte values\n");
            printf("Printing \"connection time; get time; DHT answer "
                   "(0 = OK, 1 = error, 2 = retry, or some value)\n");
            printf("Doing %s iterations\n", argv[2]);
            srand(time(NULL));
            int ra = 0;
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    /* consecutive key instead of random as the variable says */
                    ra= (n + 1) * 1000000; 
                    sprintf(key_rand, "%.d", ra);
                    HIP_DEBUG("Consecutive key  %s\n", key_rand);
                    s = init_dht_gateway_socket(s);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999;999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            gettimeofday(&stat_before, NULL);
                            /* TTL just iter * 60 secs so values can be found in get test */
                            ret = opendht_put(s, (unsigned char *)key_rand,
                                              (unsigned char *)val_onekilo, 
                                              (unsigned char *)host_addr,5851,(iter* 60)); 
                            ret = opendht_read_response(s, dht_response); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f;%.6f;%s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response);
                        }
                }
        }
    else if (argv[1][0] == '8')
        {
            memset(val_onekilo,'a',sizeof(val_onekilo));
            printf("Put test times with consecutive keys and 985 byte values"
                   " with 5 sec sleep between puts\n");
            printf("Printing \"connection time; get time; DHT answer\n");
            printf("(0 = OK, 1 = error, 2 = retry, or some value)\n");
            printf("Doing %s iterations\n", argv[2]);
            srand(time(NULL));
            int ra = 0;
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    /* consecutive key instead of random as the variable says */
                    ra= (n + 1 ) * 1000000; 
                    sprintf(key_rand, "%.d", ra);
                    HIP_DEBUG("Consecutive key  %s\n", key_rand);
                    s = init_dht_gateway_socket(s);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999;999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            gettimeofday(&stat_before, NULL);
                            /* TTL just iter * 60 secs so values can be found in get test */
                            ret = opendht_put(s, (unsigned char *)key_rand,
                                              (unsigned char *)val_onekilo, 
                                              (unsigned char *)host_addr,5851,(iter * 60)); 
                            ret = opendht_read_response(s, dht_response); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f;%.6f;%s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response);
                            sleep(5);
                        }
                }
        }        
    else if (argv[1][0] == '9')
        {     
            printf("Get test times with consecutive keys (do number 7 or 8 first,"
                   " otherwise it will be num 2)\n");
            printf("Printing \"connection time; get time; DHT answer\n");
            printf("(0 = OK, 1 = error, 2 = retry, or some value "
                   "(printing just first character, its just 985 'a's))\n");
            printf("Doing %s iterations\n", argv[2]);
            srand(time(NULL));
            int ra = 0;
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    /* consecutive key instead of random as the variable says */
                    ra= (n + 1) * 1000000; 
                    sprintf(key_rand, "%.d", ra);
                    HIP_DEBUG("Consecutive key  %s\n", key_rand);
                    s = init_dht_gateway_socket(s);
                    gettimeofday(&conn_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    gettimeofday(&conn_after, NULL);
                    if (error < 0)
                        {
                            printf("999;999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            gettimeofday(&stat_before, NULL);
                            ret = opendht_get(s, (unsigned char *)key_rand, 
                                              (unsigned char *)host_addr, 5851); 
                            ret = opendht_read_response(s, dht_response); 
                            gettimeofday(&stat_after, NULL);
                            close(s);
                            /* Print findings*/
                            conn_diff_sec = (conn_after.tv_sec - conn_before.tv_sec) *1000000;
                            conn_diff_usec = conn_after.tv_usec - conn_before.tv_usec;
                            stat_diff_sec = (stat_after.tv_sec - stat_before.tv_sec) *1000000;
                            stat_diff_usec = stat_after.tv_usec - stat_before.tv_usec;
                            printf("%.6f;%.6f;%s\n", 
                                   (conn_diff_sec + conn_diff_usec)/1000000.0, 
                                   (stat_diff_sec + stat_diff_usec)/1000000.0,
                                   dht_response);
                        }
                }

        }
    else if (argv[1][0] == 'a')
        {
            printf("Rm test times, put_removable, rm, put_removable\n"
                   "get (check that it is the new one you get)\n"
                   "sleep for rm ttl again...\n");
            printf("Printing \"put time; rm time; put time; DHT answer\n");
            printf("(0 = OK, 1 = error, 2 = retry, or some value)\n");
            printf("Doing %s iterations\n", argv[2]);
            
            for (n = 0; n < iter; n++)
                {
                    HIP_DEBUG("Iteration no %d\n",n);
                    /* first put removabe */
                    s = init_dht_gateway_socket(s);
                    gettimeofday(&put_rm_before, NULL);
                    error = connect_dht_gateway(s, serving_gateway, 1);
                    if (error < 0)
                        {
                            printf("9999;999;999\n");
                            close(s);
                        }
                    else 
                        {
                            ret = 0;
                            memset(dht_response2, '\0', sizeof(dht_response2));
                            ret = opendht_put_rm(s, 
                                                 (unsigned char *)val_host_test,
                                                 (unsigned char *)val_something,
                                                 (unsigned char *)secret_str,
                                                 (unsigned char *)host_addr,5851,20);   
                            ret = opendht_read_response(s, dht_response2); 
                            gettimeofday(&put_rm_after, NULL);
                            if (ret == -1) exit(1);
                            close(s);
                            /* removing the value */
                            s = init_dht_gateway_socket(s);
                            gettimeofday(&rm_before, NULL);
                            error = connect_dht_gateway(s, serving_gateway, 1);
                            if (error < 0) 
                                {
                                    printf("999;9999;999\n");
                                    close(s);
                                }
                            else
                                {
                                    ret = 0;
                                    memset(dht_response2, '\0', sizeof(dht_response2));
                                    ret = opendht_rm(s, 
                                                     (unsigned char *)val_host_test,
                                                     (unsigned char *)val_something,
                                                     (unsigned char *)secret_str,
                                                     (unsigned char *)host_addr,5851,20);   
                                    ret = opendht_read_response(s, dht_response2); 
                                    gettimeofday(&rm_after, NULL);
                                    if (ret == -1) exit(1);
                                    close(s);
                                    /* putting a new value */
          
                                    s = init_dht_gateway_socket(s);
                                    gettimeofday(&put_rm2_before, NULL);
                                    error = connect_dht_gateway(s, serving_gateway, 1);
                                    if (error < 0)
                                        {
                                            printf("999;999;9999\n");
                                            close(s);
                                        }
                                    else 
                                        {
                                            ret = 0;
                                            memset(dht_response2, '\0', sizeof(dht_response2));
                                            ret = opendht_put_rm(s, 
                                                                 (unsigned char *)val_host_test,
                                                                 (unsigned char *)val_something,
                                                                 (unsigned char *)secret_str,
                                                                 (unsigned char *)host_addr,
                                                                 5851,20);   
                                            ret = opendht_read_response(s, dht_response2); 
                                            gettimeofday(&put_rm2_after, NULL);
                                            if (ret == -1) exit(1);
                                            close(s);

                                            /* Print findings*/
                                            put_rm_diff_sec = (put_rm_after.tv_sec 
                                                               - put_rm_before.tv_sec) *1000000;
                                            put_rm_diff_usec = (put_rm_after.tv_usec 
                                                                - put_rm_before.tv_usec);
                                            
                                            rm_diff_sec = (rm_after.tv_sec 
                                                           - rm_before.tv_sec) *1000000;
                                            rm_diff_usec = (rm_after.tv_usec 
                                                            - rm_before.tv_usec);

                                            put_rm2_diff_sec = (put_rm2_after.tv_sec 
                                                                - put_rm2_before.tv_sec) *1000000;
                                            put_rm2_diff_usec = (put_rm2_after.tv_usec 
                                                         - put_rm2_before.tv_usec);
                                            
                                            printf("%.6f;%.6f;%.6f;%s\n", 
                                                   ((put_rm_diff_sec + put_rm_diff_usec)
                                                    /1000000.0),
                                                   ((rm_diff_sec + rm_diff_usec)/1000000.0),
                                                   ((put_rm2_diff_sec + 
                                                    put_rm2_diff_usec)/1000000.0),
                                                   dht_response2);
                                            HIP_DEBUG("sleeping for 30 secs to get rid off "
                                                      "old values and removes\n"); 
                                            sleep(30);
                                        }
                                }
                        }
                }

        }
    else
        {
            printf("Unknown parameter, %s\n", argv[1]);
        }
}
