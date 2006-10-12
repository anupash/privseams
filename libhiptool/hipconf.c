/** @file
 * This file defines functions for configuring the the Host Identity
 * Protocol daemon (hipd).
 *
 */
#include "hipconf.h"


/**
 * Handles the hipconf commands where the type is @c run. Execute new
 * application and set environment variable "LD_PRELOAD" to as type
 * says.
 * @note In order to this function to work properly, "make install"
 * must be executed to install libraries to right paths. Also library
 * paths must be set right.
 *
 * @see
 * exec_app_types\n
 * EXEC_LOADLIB_OPP\n
 * EXEC_LOADLIB_HIP\n
 * EXEC_LOADLIB_NONE\n
 *
 * @param type   the numeric action identifier for the action to be performed.
 * @param argv   an array of pointers to the command line arguments after
 *               the action and type.
 * @param argc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
int handle_exec_application(int type, char *argv[], int argc)
{
	/* Variables. */
	char *path;
	va_list args;
	int err = 0;

	err = fork();

	if (err < 0) HIP_DEBUG("Failed to exec new application.\n");
	else if (err > 0) err = 0;
	else if(err == 0)
	{
		HIP_DEBUG("Exec new application.\n");
		if (type == EXEC_LOADLIB_HIP)
		{
			path = LIB_DIR "/libinet6.so:" LIB_DIR "/libhiptool.so";
			setenv("LD_PRELOAD", path, 1);
		}
		else
		{
			path = LIB_DIR "/libopphip.so:" LIB_DIR "/libinet6.so:" LIB_DIR "/libhiptool.so";
			setenv("LD_PRELOAD", path, 1);
		}

		HIP_DEBUG("Set following libraries to LD_PRELOAD: %s\n", type == TYPE_RUN ? "libinet6.so:libhiptool.so" : "libopphip.so:libinet6.so:libhiptool.so");
		err = execvp(argv[0], argv);
		if (err != 0)
		{
			HIP_DEBUG("Executing new application failed!\n");
			exit(1);
		}
	}

out_err:
	return (err);
}






