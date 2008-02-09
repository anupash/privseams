/** @file
 * This file defines a command line tool for configuring the the Host Identity
 * Protocol daemon (hipd).
 *
 * @author  Janne Lundberg <jlu_tcs.hut.fi>
 * @author  Miika Komu <miika_iki.fi>
 * @author  Mika Kousa <mkousa_cc.hut.fi>
 * @author  Anthony D. Joseph <adj_hiit.fi>
 * @author  Abhinav Pathak <abhinav.pathak_hiit.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @author  Anu Markkola
 * @author  Lauri Silvennoinen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>
 * @todo    add/del map
 * @todo    fix the rst kludges
 * @todo    read the output message from send_msg?
 * @bug     makefile compiles prefix of debug messages wrong for hipconf in 
 *          "make all"
 */
#include "hipconftool.h"
#include "ife.h"


/**
 * Parses command line arguments and send the appropiate message to hipd
 *
 * @param argc   the number of elements in the array.
 * @param argv   an array of pointers to the command line arguments after
 *               the action and type.
 * @return       zero on success, or negative error value on error.
 */
#ifndef HIP_UNITTEST_MODE /* Unit testing code does not compile with main */
int main(int argc, char *argv[]) {

	int err = 0;
	const char *cfile = "default";

	/* we don't want log messages via syslog */
	hip_set_logtype(LOGTYPE_STDERR);
	hip_set_logfmt(LOGFMT_SHORT);
	HIP_IFEL(hip_set_auto_logdebug(cfile), -1,
	  "Error: Cannot set the debugging parameter.\n");

	
	HIP_IFEL(hip_do_hipconf(argc, argv, 0), -2,
	  "Error: Cannot configure hip.\n");

 out_err:
	return err;

}

#endif /* HIP_UNITTEST_MODE */
