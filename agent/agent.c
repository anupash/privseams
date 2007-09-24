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
	if (force_exit < 1) HIP_ERROR("SIGINT (CTRL-C) caught, exiting agent...\n");
	else if (force_exit < 2) HIP_ERROR("SIGINT (CTRL-C) caught, still once to terminate brutally.\n");
	else
	{
		HIP_ERROR("SIGINT (CTRL-C) caught, terminating!\n");
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
	HIP_ERROR("SIGTSTP (CTRL-Z?) caught, don't do that...\n");
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
int main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind, optopt;
	int err = 0, fd, c;
	char lock_file[MAX_PATH];

	/* Initialize string variables. */
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
			read(fd, str, 64);
			HIP_ERROR("hipagent already running with pid %d\n", atoi(str));
			exit (1);
		}
		sprintf(str, "%d\n", getpid());
		write(fd, str, strlen(str)); /* record pid to lockfile */
	}
	
	/* Create config filename. */
	str_var_set("config-file", "%s/.hipagent/config", getenv("HOME"));
	/* Create database filename. */
	str_var_set("db-file", "%s/.hipagent/database", getenv("HOME"));

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
	while ((c = getopt(argc, argv, ":hl:bd")) != -1)
	{
		switch (c)
		{
		case ':':
		case '?':
		case 'h':
			fprintf(stderr, "no help available currently\n");
			goto out_err;
		
		case 'l':
			str_var_set("lang-file", optarg);
			break;
		
		case 'd':
		case 'b':
			str_var_set("daemon", "yes");
			break;
		}
	}

	/* Load language variables. */
	lang_init(str_var_get("lang"), str_var_get("lang-file"));

	if (str_var_is("daemon", "yes"))
	{
		int i = fork();
		HIP_IFEL(i < 0, -1, "fork() failed!\n");
		if (i > 0) exit(0); /* parent exits */
		setsid();
		for (i = getdtablesize(); i >= 0; --i) close(i);
		i = open("/dev/null", O_RDWR); /* open stdin */
		dup(i); /* stdout */
		dup(i); /* stderr */
		umask(027);
		chdir("/tmp");
	}

	/* Initialize GUI. */
	_HIP_DEBUG("##### 1. Initializing GUI...\n");
	HIP_IFEL(gui_init(), -1, "Failed to initialize GUI!\n");

	/* Initialize database. */
	_HIP_DEBUG("##### 2. Initializing database...\n");
	HIP_IFEL(hit_db_init(str_var_get("db-file")), -1, "Failed to load agent database!\n");
	//hit_db_add_rgroup(lang_get("default-group-name"), NULL, HIT_ACCEPT, 0);
	hit_db_add_rgroup(" deny", NULL, HIT_DENY, 0);

	/* Initialize connection to HIP daemon. */
	_HIP_DEBUG("##### 3. Initializing connection to HIP daemon...\n");
	HIP_IFEL(connhipd_init(), -1, "Failed to open connection to HIP daemon!\n");

	/* Start GUI itself. */
	_HIP_DEBUG("##### 4. Executing GUI main.\n");
	gui_main();
	
	/* Quit GUI. */
	gui_quit();
	agent_exit();
	hit_db_quit(str_var_get("db-file"));

out_err:
	connhipd_quit();
	lang_quit();
	lockf(fd, F_ULOCK, 0);
	unlink(str_var_get("pid-file"));
	str_var_quit();

	_HIP_DEBUG("##### X. Exiting application...\n");
	return (err);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

