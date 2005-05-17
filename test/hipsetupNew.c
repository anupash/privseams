#include "hipsetupNew.h"

extern char *optarg;
extern int optind, opterr, optopt;

const char *usage_str = "hipsetupNew -h for help\n"
	"hipsetupNew -m            to install hipmod module\n"
	"hipsetupNew -i peer_name  for Base Exchange Initiator\n"
	"hipsetupNew -r            for Base Exchange Responder\n"
	"hipsetupNew -s            for Base Exchange SSH\n"
	"hipsetupNew -b            for BOS (in initiator)\n"
	"\n"
	;

void usage_f()
{
	printf("Usage:\n%s\n", usage_str);
}

int init_daemon()
{
	/***************************************
	 * Initialization of hip daemon: not yet considered
	 * This has to be fixed in future, according on how to identify
	 * the user space is compiled in the kernel
	 ***************************************/
	system("killall hipd");
	/* 
	 * The path has to be decided. We assume that this is run from test/ directory 
	 * in an unstable and initial version.
	 * Later on this will changed to the only command, without specifying the
	 * path, because we will insert it into $PATH
	 */
	system("../hipd/hipd &");
	//system("hipd &");
}

int install_module(struct hip_common *msg)
{
	
	int err;
	char *opts[1];
	err = system("grep -q hipmod /proc/modules");
	if (!err){
		printf("Removing the hipmod module.\n");
		err = system("rmmod hipmod");
		if(err == -1) {
			printf("Some error occured while removing the hipmod module\n");
			return(err);
		}
	}
	
	printf("The hipmod module is being installed...\n");
	err = system("/sbin/modprobe -v hipmod");

	printf("Initializing the hipd daemon...\n");
	init_daemon();
	sleep(3);
	/*
	  $HIPL_DIR/tools/hipconf add hi default
	  This function is in hipconf.c and is handle_hi()
	*/
	opts[0] = "default";
	err = handle_hi(msg, ACTION_ADD, (const char *)opts, 1);
	return err;
}

int main(int argc, char *argv[])
{
	int c, ret, err = 0;
	struct hip_common *msg;
	char *peer_name, buf[20];
	extern char *optarg;
	
	if(argc < 2){
		printf("No args specified \n");
		usage_f();
		return 0;
	}

	msg = malloc(HIP_MAX_PACKET);
	if (!msg) {
		HIP_ERROR("malloc failed\n");
		goto out;
	}
	hip_msg_init(msg);
	
	while ((c = getopt(argc, argv, ":hmrsdbi:")) != -1)
	{
		switch (c){
		case 'h':
			usage_f();
			break;
		case 'm':
			/* Install the modules */
			ret = system("whoami | grep -q root");
			if (!ret)
				err = install_module(msg);
			else {
				HIP_ERROR("Installation must be done as root\n");
				goto out_malloc;
			}
			if (err) {
				HIP_ERROR("failed to handle msg\n");
				goto out_malloc;
			}

			/* hipconf new hi does not involve any messages to kernel */
			if (hip_get_msg_type(msg) == 0)
				goto skip_msg;

			err = hip_set_global_option(msg);
			if (err) {
				HIP_ERROR("sending msg failed\n");
				goto out_malloc;
			}
			
			break;
		case 'd':
			/* HIPL_DIR */
			/* I don't know whether this is needed anymore ...*/
			break;
		case 'i':
			/* Base Exchange Initiator */
			printf("Initiator mode\n");
			if (optarg[0] = "0")
				peer_name = NULL;
			else
				peer_name = optarg;
			sprintf(buf, "%d",DEFAULT_PORT);
			main_client_gai(IPPROTO_TCP, SOCK_STREAM, peer_name, buf);
			break;
		case 'r':
			printf("Responder mode\n");
			/* Base Exchange Responder */
			main_server(IPPROTO_TCP, DEFAULT_PORT);
			break;
		case 's':
			/* Base Exchange SSH  */
			printf("Initiator-responder mode\n");
			break;
		case 'b':
			/* BOS  */
			printf("BOS\n");
			err = handle_bos(msg, 0, (const char **) NULL, 0);
			if (err) {
				HIP_ERROR("failed to handle msg\n");
				goto out_malloc;
			}
			/* hipconf new hi does not involve any messages to kernel */
			if (hip_get_msg_type(msg) == 0)
				goto skip_msg;
			
			err = hip_set_global_option(msg);
			if (err) {
				HIP_ERROR("sending msg failed\n");
				goto out_malloc;
			}
			break;
		case ':':
			printf("Missing argument %c\n", optopt);
			usage_f();
			return(0);
		case '?':
			printf("Unknown option %c\n", optopt);
			usage_f();
			return(0);
		}
	}

skip_msg:
	
out_malloc:
	free(msg);
out:
	return err;
}
