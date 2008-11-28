#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#include "hidb.h"

#include "nsupdate.h"

int hip_nsupdate_status = 1;

void hip_set_nsupdate_status(int status) {
  hip_nsupdate_status = status;
}

int hip_get_nsupdate_status(void) {
  return hip_nsupdate_status;
}

/*
 * returns string "name=value"
 * remember to free()
 */
char *make_env(char *name, char *value)
{
 char *result = malloc(strlen(name) + 1 + strlen(value) + 1); // name,'=',value,0

 if (result == NULL)
 {
  perror("malloc");
  return NULL;
 }

 strcpy(result, name);
 strcat(result, "=");
 strcat(result, value);
 return result;
}

/*
 * Handle child exits to avoid zombies
 */
static void sig_chld (int signo)
{
	pid_t child_pid;
	int child_status; // child exit code
	child_pid = waitpid (0, &child_status, WNOHANG);
	HIP_DEBUG("pid: %d, status: %d\n", child_pid, child_status);
}

/*
 * Execute nsupdate.pl with IP and HIT given as environment variables
 */
int run_nsupdate(char *ips, char *hit)
{
	struct sigaction act;
	pid_t child_pid;

	act.sa_handler = sig_chld;

	/* We don't want to block any other signals */
	sigemptyset(&act.sa_mask);

	/*
	 * We're only interested in children that have terminated, not ones
	 * which have been stopped (eg user pressing control-Z at terminal)
	 */
	act.sa_flags = SA_NOCLDSTOP | SA_RESTART;

	/* Make the handler effective */
	if (sigaction(SIGCHLD, &act, NULL) < 0) 
	{
		perror("sigaction");
        	return ERR;
	}

	/* Let us fork to execute nsupdate as a separate process */
	child_pid=fork();

	if (child_pid<0)
	{
		perror("fork");
		return ERR;
	}
	else if (child_pid == 0) // CHILD
	{
		/* Sorry, no input */
		fclose(stdin);

		char *env_ips = make_env(VAR_IPS, ips);
		char *env_hit = make_env(VAR_HIT, hit);
		char *cmd[] = { NSUPDATE_ARG0, NULL };
		char *env[] = { env_ips, env_hit, NULL };
		HIP_DEBUG("Starting %s with %s and %s", NSUPDATE_PL, env_hit, env_ips);
		execve (NSUPDATE_PL, cmd, env);
		/* Executed only if error */
		HIP_PERROR("execve");
		exit(1); // just in case
	}
	else // PARENT
	{
		/* We execute waitpid in SIGCHLD handler */
		return OK;
	}
}

/*
 * Called from hip_for_each_hi
 */
int run_nsupdate_for_hit (struct hip_host_id_entry *entry, void *opaq)
{
	HIP_DEBUG("run_nsupdate");
	char *hit = hip_convert_hit_to_str(&entry->lhi.hit,NULL);

#define ip_str_LEN 40 // buffer for one IP address 
	char ip_str[ip_str_LEN];

#define ips_str_LEN 1024 
	char ips_str[ips_str_LEN];
	ips_str[0]=0;
	
  	hip_list_t *item, *tmp;
  	int i;


  	list_for_each_safe(item, tmp, addresses, i)
	{
		struct netdev_address *n = list_entry(item);

		struct sockaddr* tmp_sockaddr_ptr = (struct sockaddr*)&n->addr;
		struct sockaddr_in* tmp_sockaddr_in_ptr = (struct sockaddr_in*) tmp_sockaddr_ptr;
		struct sockaddr_in6* tmp_sockaddr_in6_ptr = (struct sockaddr_in6*) tmp_sockaddr_ptr;

		switch (tmp_sockaddr_ptr->sa_family)
		{
			case AF_INET:
				inet_ntop(AF_INET, & tmp_sockaddr_in_ptr->sin_addr, ip_str, ip_str_LEN);
				if (ips_str[0]!=0) // not empty
					strncat(ips_str, " ", ips_str_LEN-strlen(ips_str));
				strncat(ips_str, ip_str, ips_str_LEN-strlen(ips_str));
				break;
			case AF_INET6:
				if (IN6_IS_ADDR_V4MAPPED(&tmp_sockaddr_in6_ptr->sin6_addr)) {
					struct in_addr tmp_in_addr;
					IPV6_TO_IPV4_MAP(&tmp_sockaddr_in6_ptr->sin6_addr, &tmp_in_addr)
					inet_ntop(AF_INET, &tmp_in_addr, ip_str, ip_str_LEN);
				} else {
					inet_ntop(AF_INET6, &tmp_sockaddr_in6_ptr->sin6_addr, ip_str, ip_str_LEN);
				}

				if (ips_str[0]!=0) // not empty
					strncat(ips_str, " ", ips_str_LEN-strlen(ips_str));
				strncat(ips_str, ip_str, ips_str_LEN-strlen(ips_str));
				break;
		}
	}

	run_nsupdate(ips_str, hit);
	free(hit);
	return 0;
}

/*
 * Update records for all hits. The host should be able to send packets to HITs to modify the DNS records
 */ 
int nsupdate(void)
{
	HIP_DEBUG("Updating dns records...");
	hip_for_each_hi(run_nsupdate_for_hit, NULL);
}

/*
 * Just call run_nsupdate with some values for debugging
 */
int junk_main(void)
{
	int ret;

	ret = run_nsupdate("193.167.187.3 193.167.187.5","def");
	printf("ret=%d\n", ret);
	sleep(1);

	/* wait for children */	
	while (1)
	{
		sleep(1);
	}
	return 0;
}
