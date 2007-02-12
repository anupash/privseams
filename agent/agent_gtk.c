/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "agent.h"


/******************************************************************************/
/** Catch SIGINT. */
void sig_catch_int(int signum)
{
	static int force_exit = 0;
	
	signal(signum, sig_catch_int);
	agent_exit();
	if (force_exit < 1) HIP_DEBUG("SIGINT (CTRL-C) caught, exiting agent...\n");
	else if (force_exit < 2) HIP_DEBUG("SIGINT (CTRL-C) caught, still once to terminate brutally.\n");
	else
	{
		HIP_DEBUG("SIGINT (CTRL-C) caught, terminating!\n");
		exit(1);
	}

	force_exit++;
}
/* END OF FUNCTION */


/******************************************************************************/
/** Catch SIGTSTP. */
void sig_catch_tstp(int signum)
{
	signal(signum, sig_catch_tstp);
	HIP_DEBUG("SIGTSTP (CTRL-Z?) caught, don't do that...\n");
}
/* END OF FUNCTION */


/******************************************************************************/
/** Catch SIGCHLD. */
void sig_catch_chld(int signum) 
{ 
	/* Variables. */
	union wait status;
	int pid, i;
	
	signal(signum, sig_catch_chld);

	/* Get child process status, so it wont be left as zombie for long time. */
	while ((pid = wait3(&status, WNOHANG, 0)) > 0)
	{
		/* Maybe do something.. */
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/** Catch SIGTERM. */
void sig_catch_term(int signum)
{
	signal(signum, sig_catch_tstp);
	HIP_ERROR("SIGTERM caught, force exit now!\n");
	exit (1);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	main().
*/
int main(int argn, char *argv[])
{
	/* Variables. */
	int err = 0, fd;

	/* Write pid to file. */
/*	unlink(HIP_AGENT_LOCK_FILE);
	fd = open(HIP_AGENT_LOCK_FILE, O_RDWR | O_CREAT, 0644);
	if (fd > 0)
	{
		char str[64];
		/* Dont lock now, make this feature available later. */
		// if (lockf(i, F_TLOCK, 0) < 0) exit (1);
		/* Only first instance continues. */
//		sprintf(str, "%d\n", getpid());
//		write(fd, str, strlen(str)); /* record pid to lockfile */
//	}
	
	/* Initialize string variables. */
	HIP_IFEL(str_var_init(), -1, "Failed to initialize strvars!\n");
	
	/* Create config path. */
	str_var_set("config-path", "%s/.hipagent", getenv("HOME"));
	mkdir(str_var_get("config-path"), 0700);
	/* Create config filename. */
	str_var_set("config-file", "%s/.hipagent/config", getenv("HOME"));
	/* Create database filename. */
	str_var_set("db-file", "%s/.hipagent/database", getenv("HOME"));

	/* Check command line options. */
	term_set_mode(TERM_MODE_NONE);
	err = -1;
	if (argn == 2)
	{
		if (argv[1][0] == '-')
		{
			if (argv[1][1] == 's')
			{
				term_set_mode(TERM_MODE_SERVER);
				err = 0;
			}
		}
	}
	if (argn == 3)
	{
		if (argv[1][0] == '-')
		{
			if (argv[1][1] == 'c')
			{
				term_set_mode(TERM_MODE_CLIENT);
				term_set_server_addr(argv[2]);
				err = 0;
			}
		}
	}
	if (argn == 1) err = 0;

	HIP_IFEL(err, -1, "Invalid command line parameters.\n");

	/* Read config. */
	err = config_read(str_var_get("config-file"));
	if (err) HIP_ERROR("Could not read config file.\n");
	lang_init(str_var_get("lang"));

	/* Set some random seed. */
	srand(time(NULL));

	/* Set signalling. */
	signal(SIGINT, sig_catch_int);
	signal(SIGCHLD, sig_catch_chld);
	signal(SIGTERM, sig_catch_term);

	/* Initialize GUI. */
	HIP_DEBUG("##### 1. Initializing GUI...\n");
	HIP_IFEL(gui_init(), -1, "Failed to initialize GUI!\n");

	/* Initialize database. */
	HIP_DEBUG("##### 2. Initializing database...\n");
	HIP_IFEL(hit_db_init(str_var_get("db-file")), -1, "Failed to load agent database!\n");
	hit_db_add_rgroup(lang_get("default-group-name"), NULL, HIT_ACCEPT, 0);
	hit_db_add_rgroup(" deny", NULL, HIT_DENY, 0);

	/* Initialize connection to HIP daemon. */
	HIP_DEBUG("##### 3. Initializing connection to HIP daemon...\n");
#ifndef CONFIG_HIP_DEBUG
	HIP_IFEL(connhipd_init(), -1, "Failed to open connection to HIP daemon!\n");
#else
	/*
		If in debug mode, try to execute daemon from GUI,
		if connection to daemon fails.
	*/
	err = connhipd_init();
	
	/*
		If connection to daemon failed, assume that daemon
		is not running and try to fork it.
	*/
	if (err != 0 && 0)
	{
		HIP_DEBUG("Trying to execute daemon...\n");
		err = fork();
		
		if (err < 0) HIP_DEBUG("fork() failed!\n");
		else if (err > 0)
		{
			/* Wait for daemon to start. */
			sleep(2);
			/* Initialize connection to HIP daemon. */
			err = connhipd_init();
		}
		else if(err == 0)
		{
			err = execlp("./hipd/hipd", "", (char *)0);
			if (err != 0)
			{
				HIP_DEBUG("Executing HIP daemon failed!\n");
				exit(1);
			}
		}
	}

#endif

	HIP_DEBUG("##### 4. Executing GUI main.\n");
	gui_main();

	agent_exit();

out_err:
	connhipd_quit();
	hit_db_quit(str_var_get("db-file"));
	lang_quit();
	str_var_quit();

	HIP_DEBUG("##### X. Exiting application...\n");
	return (err);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

