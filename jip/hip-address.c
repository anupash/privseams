/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

#include "jip_HipAddress.h"

#include <string.h>
#include <netdb.h>

static jmethodID init_id;

JNIEXPORT void JNICALL
Java_jip_HipAddress_nativeInit (JNIEnv *env, jclass cls)
{
    puts("HipAddress.nativeInit");
    fflush(stdout);
    init_id = (*env)->GetMethodID(env, cls, "<init>", "(S)V");
}

JNIEXPORT jobjectArray JNICALL
Java_jip_HipAddress_getAllByName (JNIEnv *env, jclass cls, jstring host)
{
    const jbyte *s = (*env)->GetStringUTFChars(env, host, NULL);
    struct endpointinfo hints, *res, *ai;
    int error, size, i;
    jobjectArray result;
    const jbyte *khost = NULL, *kport = NULL;
    int local = 0;
    printf("EidByName: <%s>\n", s);
    fflush(stdout);
    memset(&hints, 0, sizeof hints);
    hints.ei_family = PF_HIP;
    hints.ei_socktype = SOCK_STREAM;
    puts("Calling");
    fflush(stdout);
    if (s == NULL || strcmp(s, "") == 0 || strncmp(s, "localhost", 9) == 0) {
	local = 1;
	kport = "1";
    } else {
	khost = s;
    }
    error = getendpointinfo(khost, kport, &hints, &res);
    puts("Called");
    fflush(stdout);
    if (error) {
	char buffer[256];
	jclass uh_ex_cls =
	    (*env)->FindClass(env, "java/net/UnknownHostException");
	snprintf(buffer, sizeof buffer, "Getendpointinfo failed %d: %s", error,
		 gepi_strerror(error));
	if (uh_ex_cls != NULL) {
	    (*env)->ThrowNew(env, uh_ex_cls, buffer);
	}
	return NULL;
    }
    printf("%p\n", res);
    fflush(stdout);
    (*env)->ReleaseStringUTFChars(env, host, s);
    size = 0;
    for (ai = res; ai != NULL; ai = ai->ei_next) {
	size += 1;
	if (local) {
	    struct sockaddr_eid *addr = (struct sockaddr_eid *) ai->ei_endpoint;
	    addr->eid_port = 0;
	}
    }
    result = (*env)->NewObjectArray(env, size, cls, NULL);
    if (result == NULL) {
	return NULL;
    }
    for (ai = res, i = 0; ai != NULL; ai = ai->ei_next, i++) {
	struct sockaddr_eid *addr = (struct sockaddr_eid *) ai->ei_endpoint;
	jobject hip_addr = (*env)->NewObject(env, cls, init_id, addr->eid_val);
	(*env)->SetObjectArrayElement(env, result, i, hip_addr);
	(*env)->DeleteLocalRef(env, hip_addr);
    }
    return result;
}
