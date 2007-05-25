#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#include "hidb.h"

#define VAR_IPS "IPS"
#define VAR_HIT "HIT"
#define NSUPDATE "/etc/hip/nsupdate.pl"
#define NSUPDATE_ARG0 "nsupdate.pl"


#define ERR -1

/*
 * return string "name=value"
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
	printf("pid: %d, status: %d\n", child_pid, child_status);
}

/*
 * Execute NSUPDATE with IP and HIT given as environment variables
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
		execve (NSUPDATE, cmd, env);
		perror("execve");
		return ERR;
	}
	else // PARENT
	{
		/* We execute waitpid in SIGCHLD handler */
		return 0;
	}
}

/*
 * Called from hip_for_each_hi
 */
int run_nsupdate_for_hit (struct hip_host_id_entry *entry, void *opaq)
{
	HIP_DEBUG("run_nsupdate");
	char *hit = hip_convert_hit_to_str(&entry->lhi.hit,NULL);


	struct netdev_address *n, *t;
#define bufLEN 1024
	char buf[bufLEN];
#define sLEN 40
	char s[sLEN];
	buf[0]=0;
	
	struct sockaddr* tmp_sockaddr_ptr;
	struct sockaddr_in* tmp_sockaddr_in_ptr;
	struct sockaddr_in6* tmp_sockaddr_in6_ptr;
	struct in_addr tmp_in_addr;

  	hip_list_t *item, *tmp;
  	int i;


  	list_for_each_safe(item, tmp, addresses, i)
	{
		n = list_entry(item);

//	list_for_each_entry_safe(n, t, &addresses, next_hit)
//	{
		tmp_sockaddr_ptr = (struct sockaddr*)&n->addr;
		switch (tmp_sockaddr_ptr->sa_family)
		{
			case AF_INET:
				tmp_sockaddr_in_ptr = (struct sockaddr_in*) tmp_sockaddr_ptr;
				inet_ntop(AF_INET, &tmp_sockaddr_in_ptr->sin_addr, s, sLEN);
				strncat(buf, s, bufLEN-strlen(buf));
				strncat(buf, ",", bufLEN-strlen(buf));
				break;
			case AF_INET6:
				tmp_sockaddr_in6_ptr = (struct sockaddr_in6*) tmp_sockaddr_ptr;
				if (IN6_IS_ADDR_V4MAPPED(&tmp_sockaddr_in6_ptr->sin6_addr)) {
					IPV6_TO_IPV4_MAP(&tmp_sockaddr_in6_ptr->sin6_addr, &tmp_in_addr)
					inet_ntop(AF_INET, &tmp_in_addr, s, sLEN);
				} else {
					inet_ntop(AF_INET6, &tmp_sockaddr_in6_ptr->sin6_addr, s, sLEN);
				}
					strncat(buf, s, bufLEN-strlen(buf));
					strncat(buf, ",", bufLEN-strlen(buf));
				break;
		}
	}

	run_nsupdate(buf, hit);
	free(hit);
	return 0;
}

/*
 * Update records for all hits 
 */ 
int nsupdate(void)
{
	HIP_DEBUG("Updating dns records...");
	hip_for_each_hi(run_nsupdate_for_hit, NULL);
}

/*
 * Just call run_nsupdate with some values
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
