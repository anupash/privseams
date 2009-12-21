/**
 * @file agent/agent.c
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * This file contains all the necessary signal handlers for the agent. The signal handlers
 * defined in this file are only used in the main() of this file. 
 *
 * @brief Main file for agent containing signal handlers and initialization
 *
 * @author: Antti Partanen <aehparta@cc.hut.fi>
 * @author: Samu Varjonen <samu.varjonen@hiit.fi>
 *
 * @note:   HIPU: use --disable-agent to get rid of the gtk and gthread dependencies
 **/
#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include <fcntl.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <wait.h>
#include <unistd.h>
#include <time.h>

#ifndef __u32
/* Fedore Core 3/4 and Enterprise linux 4 is broken. */
#  include <linux/types.h>
#endif

#include "agent.h"
#include "tools.h"
#include "gui_interface.h"
#include "connhipd.h"
#include "language.h"
#include "libhipcore/sqlitedbapi.h"
#include "libhipgui/hipgui.h"
#include "libhipcore/hip_capability.h"


/* global db for agent to see */
sqlite3 * agent_db = NULL;
int init_in_progress = 0;

/**
 * sig_catch_int - Function to catch the signal interrupt so we can cleanly close databases.
 * Real exit happens after three interrupts.
 *
 * @note used as a function pointer to signal() and only in main() of this file
 *
 * @param signum signal number
 * @return void
 **/
static void 
sig_catch_int(int signum)
{
	static int force_exit = 0;
	
	signal(signum, sig_catch_int);
	agent_exit();
	if (force_exit < 1) HIP_ERROR("SIGINT (CTRL-C) caught, exiting agent...\n");
	else if (force_exit < 2) HIP_ERROR("SIGINT (CTRL-C) caught, still once to terminate brutally.\n");
	else
	{
		HIP_ERROR("SIGINT (CTRL-C) caught, terminating!\n");
                hip_sqlite_close_db(agent_db);    
		exit(1);
	}

	force_exit++;
}
 
/* 
   Function to catch the signal stop. We do not want to stop.
   Called only from this file.
*/
static void 
sig_catch_tstp(int signum)
{
	signal(signum, sig_catch_tstp);
	HIP_ERROR("SIGTSTP (CTRL-Z?) caught, don't do that...\n");
}

/**
 * sig_catch_chld - Function to catch the signal child from child process so we can read 
 * the pid and reap them before they are zombified.
 *
 * @note used as a function pointer to signal() and only in main() of this file
 *
 * @param signum signal number
 * @return void
 **/
static void 
sig_catch_chld(int signum) 
{ 
	union wait status;
	int pid;
	
	signal(signum, sig_catch_chld);

	while ((pid = wait3(&status, WNOHANG, 0)) > 0)
	{
		/* Maybe do something.. */
	}
}

/**
 * sig_catch_term - Function to catch the signal terminate and exiting immediately when catched.
 *
 * @note used as a function pointer to signal() and only in main() of this file
 *
 * @param signum signal number
 * @return void
 **/
static void 
sig_catch_term(int signum)
{
	signal(signum, sig_catch_tstp);
	HIP_ERROR("SIGTERM caught, force exit now!\n");
	exit (1);
}

/**
 * main - Function to start the HIPL agent. The initialization of the daemon is: 
 *        creation of socket for hipd communication, 
 *        lowering the privileges to nobody, 
 *        creating a pid file, 
 *        reading/creating configuration file, 
 *        reading/creating database file, 
 *        command line opts,
 *        set signal handlers,
 *        setting the language, 
 *        initializing the GUI, 
 *        initializing the database, 
 *        opening the socket to hipd,
 *        and calling the main loop of the gui
 * 
 * @note accepts commandline parameters h and l. "h" is for help that currently offers none
 *       and l is for setting of a language file (finnish and english provided)
 *
 * @param argc number of commandline parameters
 * @param argv[] table containing the commandline parameters
 * @return negative on error
 **/
int main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind, optopt;
	int err = 0, fd = 0, c;

	HIP_IFEL((geteuid() != 0), -1, "agent must be started with sudo\n");

	/* Open socket to communicate with daemon, then drop from root to user */
	HIP_IFE(connhipd_init_sock(), -1);
#ifdef CONFIG_HIP_PRIVSEP
	HIP_IFEL(hip_set_lowcapability(1), -1, "Failed to reduce priviledges\n");
#endif /* CONFIG_HIP_PRIVSEP */

	HIP_IFEL(str_var_init(), -1, "str_var_init() failed!\n");
	/* Create config path. */
	str_var_set("config-path", "%s/.hipagent", getenv("HOME"));
	mkdir(str_var_get("config-path"), 0700);
	str_var_set("pid-file", "%s/pid", str_var_get("config-path"));

	/* Write pid to file. */
	fd = open(str_var_get("pid-file"), O_RDWR | O_CREAT, 0644);
	if (fd > 0)
	{
		char str[64];
		/* Only first instance continues. */
		if (lockf(fd, F_TLOCK, 0) < 0)
		{
			if( read(fd, str, 64) == -1 ){
				HIP_ERROR("hipagent already running with pid %d\n", atoi(str));
			} else {
				HIP_ERROR("Lock read failed");
			}
			exit (1);
		}
		sprintf(str, "%d\n", getpid());
		/* record pid to lockfile */
		if ( write(fd, str, strlen(str) == -1) ) {
			HIP_ERROR("Cannot write to lockfile");
		}
	}	
	
	/* Create config filename. */
	str_var_set("config-file", "%s/.hipagent/config", getenv("HOME"));
	/* Create database filename. */
	str_var_set("db-file", "%s/.hipagent/database.db", getenv("HOME"));

	/* Read config. */
	err = config_read(str_var_get("config-file"));
	if (err) HIP_ERROR("Could not read config file.\n");

	/* Set some random seed. */
	srand(time(NULL));

	/* Set signalling. */
	signal(SIGINT, sig_catch_int);
	signal(SIGCHLD, sig_catch_chld);
	signal(SIGTERM, sig_catch_term);

	/* Parse command line options. */
	while ((c = getopt(argc, argv, ":hl")) != -1)
	{
		switch (c)
		{
		case ':':
		case 'h':
			fprintf(stderr, "no help available currently\n");
			goto out_err;
		
		case 'l':
			str_var_set("lang-file", optarg);
			break;
		}
	}

	/* Load language variables. */
	lang_init(str_var_get("lang"), str_var_get("lang-file"));

	_HIP_DEBUG("##### 1. Initializing GUI...\n");
	HIP_IFEL(gui_init(), -1, "Failed to initialize GUI!\n");

	_HIP_DEBUG("##### 2. Initializing database...\n");
	HIP_IFEL(hit_db_init(str_var_get("db-file")), -1, "Failed to load agent database!\n");
	//hit_db_add_rgroup(lang_get("default-group-name"), NULL, HIT_ACCEPT, 0);
	hit_db_add_rgroup(" deny", NULL, HIT_DENY, 0);

	_HIP_DEBUG("##### 3. Connecting to HIP daemon...\n");
	HIP_IFEL(connhipd_run_thread(), -1, "Failed to connect to daemon\n");

	_HIP_DEBUG("##### 4. Executing GUI main.\n");
	gui_main();

	gui_quit();
	agent_exit();
	hit_db_quit();

out_err:
	connhipd_quit();
	lockf(fd, F_ULOCK, 0);
	unlink(str_var_get("pid-file"));
	str_var_quit();

	_HIP_DEBUG("##### X. Exiting application...\n");
	return (err);
}
