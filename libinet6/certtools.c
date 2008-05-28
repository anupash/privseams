/** @file
 * This file defines the certificate building and verification functions to use with HIP
 *
 * Syntax in the names of functions is as follows, hip_cert_XX_YY_VV(), where 
 *   XX is the certificate type
 *   YY is build or verify
 *   VV is what the function really does like sign etc.
 *
 * @author Samu Varjonen
 * @version 0.1
 * @date 31.3.2008
 *
 */
#include "certtools.h"

/*******************************************************************************
 * BUILDING FUNCTIONS FOR SPKI                                                 *
 *******************************************************************************/

/**  
 * Function to build the create minimal SPKI cert  
 * @param minimal_content holds the struct hip_cert_spki_info containing 
 *                        the minimal needed information for cert object, 
 *                        also contains the char table where the cert object 
 *                        is to be stored
 * @param issuer_type With HIP its HIT
 * @param issuer HIT in representation encoding 2001:001...
 * @param subject_type With HIP its HIT
 * @param subject HIT in representation encoding 2001:001...
 * @param not_before time in timeval before which the cert should not be used
 * @param not_after time in timeval after which the cert should not be used
 *
 * @return 0 if ok -1 if error
 */
int hip_cert_spki_create_cert(struct hip_cert_spki_info * content,
                              char * issuer_type, struct in6_addr * issuer,
                              char * subject_type, struct in6_addr * subject,
                              time_t * not_before, time_t * not_after) {
	int err = 0;
        char * tmp_issuer;
        char * tmp_subject;
        char * tmp_before;
        char * tmp_after;
        struct tm *ts;
        char buf_before[80];
        char buf_after[80];
        char present_issuer[41];
        char present_subject[41];
        struct hip_common * msg;
        struct hip_cert_spki_info * returned;

        /* Malloc needed */
        tmp_issuer = malloc(128);
        if (!tmp_issuer) goto out_err;
        tmp_subject = malloc(128);
        if (!tmp_subject) goto out_err;
        tmp_before = malloc(128);
        if (!tmp_before) goto out_err;
        tmp_after = malloc(128);
        if (!tmp_after) goto out_err;
        HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, 
                 "Malloc for msg failed\n");   

        /* Memset everything */
        HIP_IFEL(!memset(buf_before, '\0', sizeof(buf_before)), -1,
                 "Failed to memset memory for tmp buffers variables\n");
        HIP_IFEL(!memset(buf_after, '\0', sizeof(buf_after)), -1,
                 "Failed to memset memory for tmp buffers variables\n");
        HIP_IFEL(!memset(tmp_issuer, '\0', sizeof(tmp_issuer)), -1,
                 "Failed to memset memory for tmp variables\n");
        HIP_IFEL(!memset(tmp_subject, '\0', sizeof(tmp_subject)), -1,
                 "Failed to memset memory for tmp variables\n");
        HIP_IFEL(!memset(tmp_before, '\0', sizeof(tmp_before)), -1,
                 "Failed to memset memory for tmp variables\n");
        HIP_IFEL(!memset(tmp_after, '\0', sizeof(tmp_after)), -1,
                 "Failed to memset memory for tmp variables\n");
        HIP_IFEL(!memset(present_issuer, '\0', sizeof(present_issuer)), -1,
                 "Failed to memset memory for tmp variables\n");
        HIP_IFEL(!memset(present_subject, '\0', sizeof(present_subject)), -1,
                 "Failed to memset memory for tmp variables\n");

        /* Make needed transforms to the date */
        _HIP_DEBUG("not_before %d not_after %d\n",*not_before,*not_after);
        /*  Format and print the time, "yyyy-mm-dd hh:mm:ss"
           (not-after "1998-04-15_00:00:00") */
        ts = localtime(not_before);
        strftime(buf_before, sizeof(buf_before), "%Y-%m-%d_%H:%M:%S", ts);
        ts = localtime(not_after);
        strftime(buf_after, sizeof(buf_after), "%Y-%m-%d_%H:%M:%S", ts);
        _HIP_DEBUG("Not before %s\n", buf_before);
        _HIP_DEBUG("Not after %s\n", buf_after);

        sprintf(tmp_before, "(not-before \"%s\")", buf_before);
        sprintf(tmp_after, "(not-after \"%s\")", buf_after);
        
        ipv6_addr_copy(&content->issuer_hit, issuer);
        hip_in6_ntop(issuer, present_issuer);        
        hip_in6_ntop(subject, present_subject);

        sprintf(tmp_issuer, "(hash %s %s)", issuer_type, present_issuer);
        sprintf(tmp_subject, "(hash %s %s)", subject_type, present_subject);

        /* Create the cert sequence */        
        HIP_IFEL(hip_cert_spki_build_cert(content), -1, 
                 "hip_cert_spki_build_cert failed\n");

        HIP_IFEL(hip_cert_spki_inject(content, "cert", tmp_after), -1, 
                 "hip_cert_spki_inject failed to inject\n");
        HIP_IFEL(hip_cert_spki_inject(content, "cert", tmp_before), -1, 
                 "hip_cert_spki_inject failed to inject\n");
        HIP_IFEL(hip_cert_spki_inject(content, "cert", "(subject )"), -1, 
                 "hip_cert_spki_inject failed to inject\n");
        HIP_IFEL(hip_cert_spki_inject(content, "subject", tmp_subject), -1, 
                 "hip_cert_spki_inject failed to inject\n");
        HIP_IFEL(hip_cert_spki_inject(content, "cert", "(issuer )"), -1, 
                 "hip_cert_spki_inject failed to inject\n");
        HIP_IFEL(hip_cert_spki_inject(content, "issuer", tmp_issuer), -1, 
                 "hip_cert_spki_inject failed to inject\n");

        /* Create the signature and the public-key sequences */

        /* Send the daemon the struct hip_cert_spki_header 
           containing the cert sequence in content->cert. 
           As a result you should get the struct back with 
           public-key and signature fields filled */

        /* build the msg to be sent to the daemon */
        HIP_IFEL(hip_build_param_cert_spki_info(msg, content), -1,
                 "Failed to build cert_info\n");         
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_CERT_SPKI_SIGN, 0), -1, 
                 "Failed to build user header\n");
        /* send and wait */
        HIP_DEBUG("Sending request to sign SPKI cert sequence to "
                  "daemon and waiting for answer\n");	
        hip_send_recv_daemon_info(msg);
        
        /* get the struct from the message sent back by the daemon */
	_HIP_DUMP_MSG(msg);
        HIP_IFEL(!(returned = hip_get_param(msg, HIP_PARAM_CERT_SPKI_INFO)), 
                 -1, "No hip_cert_spki_info struct found from daemons msg\n");

	_HIP_DEBUG("PUBLIC-KEY\n%s\nCERT\n%s\nSIGNATURE\n%s\n", returned->public_key,
		  returned->cert, returned->signature);
        memcpy(content, returned, sizeof(struct hip_cert_spki_info));

out_err:
        /* free everything malloced */
        if (tmp_before) free(tmp_before);
        if (tmp_after) free(tmp_after);
        if (tmp_issuer) free(tmp_issuer);
        if (tmp_subject) free(tmp_subject);
        if (msg) free(msg);
	return (err);
} 
 
/**
 * Function to build the basic cert object of SPKI clears public-key object
 * and signature in hip_cert_spki_header
 * @param minimal_content holds the struct hip_cert_spki_header containing 
 *                        the minimal needed information for cert object, 
 *                        also contains the char table where the cert object 
 *                        is to be stored
 *
 * @return 0 if ok -1 if error
 */
int hip_cert_spki_build_cert(struct hip_cert_spki_info * minimal_content) {
	int err = 0;
	char needed[] = "(cert )";
	memset(minimal_content->public_key, '\0', sizeof(minimal_content->public_key));
	memset(minimal_content->cert, '\0', sizeof(minimal_content->cert));
	memset(minimal_content->signature, '\0', sizeof(minimal_content->signature));
        sprintf(minimal_content->cert, "%s", needed);

out_err:
	return (err);
}

/**
 * Function for injecting objects to cert object
 *
 * @param to hip_cert_spki_info containing the char table where to insert
 * @param after is a char pointer for the regcomp after which the inject happens
 * @param what is char pointer of what to 
 *
 * @return 0 if ok and negative if error. -1 returned for example when after is NOT found
 *
 * @note Remember to inject in order last first first last, its easier
 */
int hip_cert_spki_inject(struct hip_cert_spki_info * to, 
                         char * after, char * what) {
	int err = 0, status = 0;
        regex_t re;
        regmatch_t pm[1];
        char * tmp_cert;        

        _HIP_DEBUG("Before inject:\n%s\n",to->cert);
        _HIP_DEBUG("Inserting \"%s\" after \"%s\"\n", what, after);       
        tmp_cert = malloc(strlen(to->cert) + strlen(what) + 1);
        if (!tmp_cert) return(-1);
        HIP_IFEL(!memset(tmp_cert, 0, sizeof(tmp_cert)), -1,
                 "Failed to memset temporary workspace\n");        
        /* Compiling the regular expression */
        HIP_IFEL(regcomp(&re, after, REG_EXTENDED), -1, 
                 "Compilation of the regular expression failed\n");       
        /* Running the regular expression */
        HIP_IFEL((status = regexec(&re, to->cert, 1, pm, 0)), -1,
                 "Handling of regular expression failed\n");
        _HIP_DEBUG("Found \"%s\" at %d and it ends at %d\n",
                  after, pm[0].rm_so, pm[0].rm_eo);
        /* Using tmp char table to do the inject (remember the terminators)
           first the beginning */
        snprintf(tmp_cert, pm[0].rm_eo + 2, "%s", to->cert);
        /* Then the middle part to be injected */
        snprintf(&tmp_cert[pm[0].rm_eo + 1], strlen(what) + 1, "%s", what);
        /* then glue back the rest of the original at the end */
        snprintf(&tmp_cert[(pm[0].rm_eo + strlen(what) + 1)], 
                (strlen(to->cert) - pm[0].rm_eo), "%s", &to->cert[pm[0].rm_eo + 1]);
        /* move tmp to the result */
        sprintf(to->cert, "%s", tmp_cert);
        _HIP_DEBUG("After inject:\n%s\n",to->cert);
out_err:
        free(tmp_cert);
	return (err);
}

/**
 * Function that takes the cert in char and constructs hip_cert_spki_info from it
 *
 * @param from char pointer to the whole certificate
 * @param to hip_cert_spki_info containing the char table where to insert
 *
 * @return 0 if ok and negative if error. 
 */
int hip_cert_spki_char2certinfo(char * from, struct hip_cert_spki_info * to) {
        int err = 0, start = 0, stop = 0;
        /* 
           p_rule looks for string "(public_key " after which there can be
           pretty much anything until string "|)))" is encountered.
           This is the public-key sequence.
        */
        char p_rule[] = "[(]public_key [ A-Za-z0-9+|/()#=-]*[|][)][)][)]";
        /* 
           c_rule looks for string "(cert " after which there can be
           pretty much anything until string '"))' is encountered.
           This is the cert sequence.
        */ 
        char c_rule[] = "[(]cert [ A-Za-z0-9+|/():=_\"-]*[\"][)][)]"; //\" is one char  
        /* 
           s_rule looks for string "(signature " after which there can be
           pretty much anything until string "|))" is encountered.
           This is the signature sequence.
        */
        char s_rule[] = "[(]signature [ A-Za-z0-9+/|()=]*[|][)][)]";
        
        _HIP_DEBUG("FROM %s\n", from);

        /* Look for the public key */ 
        HIP_IFEL(hip_cert_regex(p_rule, from , &start, &stop), -1,
                 "Failed to run hip_cert_regex (public-key)\n");
        _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
        snprintf(to->public_key, (stop-start) + 1,"%s", &from[start]);

        /* Look for the cert sequence */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(c_rule, from, &start, &stop), -1,
                 "Failed to run hip_cert_regex (cert)\n");
        _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
        snprintf(to->cert, (stop-start) + 1,"%s", &from[start]);        

        /* look for the signature sequence */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(s_rule, from, &start, &stop), -1,
                 "Failed to run hip_cert_regex (signature)\n");
        _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
        snprintf(to->signature, (stop-start) + 1,"%s", &from[start]);
        
        _HIP_DEBUG("PK %s\nCert %s\nSign %s\n",
                  to->public_key, to->cert, to->signature);

 out_err:
        return(err);
}

/**
 * Function that wraps regular expression stuff and gives the answer :)
 *
 * @param what is a char pointer to the rule used in the search (POSIX)
 * @param from where are we looking for it char pointer
 * @param answer to the question in regmatch_t
 *
 * @return 0 if ok and negative if error. 
 * 
 * @note Be carefull with the what so you get what you want :)
 */
int hip_cert_regex(char * what, char * from, int * start, int * stop) {
        int err = 0, status = 0, i = 0;
        regex_t re;
        regmatch_t answer[1];
                
        /* Compiling the regular expression */
        HIP_IFEL(regcomp(&re, what, REG_EXTENDED), -1, 
                 "Compilation of the regular expression failed\n");       
        /* Running the regular expression */
        HIP_IFEL((status = regexec(&re, from, 1, answer, 0)), -1,
                 "Handling of regular expression failed\n");
        _HIP_DEBUG("Found \"%s\" at %d and it ends at %d\n",
                  what, answer[0].rm_so, answer[0].rm_eo); 

        *start = answer[0].rm_so;
        *stop = answer[0].rm_eo;

        /* Just for debugging do NOT leave these 2 lines uncommented */
        /*
        for (i = answer[0].rm_so; i < answer[0].rm_eo; i++) printf("%c", from[i]);
        printf("\n");
        */
 out_err:
        return (err);
}

/**
 * Function that sends the given hip_cert_spki_info to the daemon to verification
 *
 * @param to_verification is the cert to be verified
 *
 * @return 0 if ok and negative if error or unsuccesfull. 
 *
 * @note use hip_cert_spki_char2certinfo to build the hip_cert_spki_info
 */
int hip_cert_send_to_verification(struct hip_cert_spki_info * to_verification) {
        int err = 0;
        struct hip_common * msg;
        struct hip_cert_spki_info * returned;

        HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, 
                 "Malloc for msg failed\n");   
        hip_msg_init(msg);
        /* build the msg to be sent to the daemon */
        HIP_IFEL(hip_build_param_cert_spki_info(msg, to_verification), -1,
                 "Failed to build cert_info\n");         
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_CERT_SPKI_VERIFY, 0), -1, 
                 "Failed to build user header\n");

        /* send and wait */
        HIP_DEBUG("Sending request to verify SPKI cert to "
                  "daemon and waiting for answer\n");	
        hip_send_recv_daemon_info(msg);        
        
        HIP_IFEL(!(returned = hip_get_param(msg, HIP_PARAM_CERT_SPKI_INFO)), 
                 -1, "No hip_cert_spki_info struct found from daemons msg\n");
         
	_HIP_DEBUG("Success = %d (should be 0 if OK\n", returned->success);
        memcpy(to_verification, returned, sizeof(struct hip_cert_spki_info));

 out_err:
        if (msg) free(msg);
        return (err);
}
