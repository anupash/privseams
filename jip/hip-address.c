/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

#include "jip_HipAddress.h"

#include <netdb.h>

JNIEXPORT jobjectArray JNICALL
Java_jip_HipAddress_getAddresses (JNIEnv *env, jclass cls, jstring host)
{
    const jbyte *s = (*env)->GetStringUTFChars(env, host, NULL);
    struct addrinfo hints, *res, *ai;
    int error, size, i;
    jobjectArray result;
    jclass byte_array_cls;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET6;
    hints.ai_flags = AI_HIP;
    error = getaddrinfo(s, NULL, &hints, &res);
    if (error) {
	char buffer[256];
	jclass uh_ex_cls =
	    (*env)->FindClass(env, "java/net/UnknownHostException");
	snprintf(buffer, sizeof buffer, "Getaddrinfo failed %d: %s", error,
		 gai_strerror(error));
	if (uh_ex_cls != NULL) {
	    (*env)->ThrowNew(env, uh_ex_cls, buffer);
	}
	return NULL;
    }
    (*env)->ReleaseStringUTFChars(env, host, s);
    size = 0;
    for (ai = res; ai != NULL; ai = ai->ai_next) {
	size += 1;
    }
    byte_array_cls = (*env)->FindClass(env, "[B");
    if (byte_array_cls == NULL) {
	return NULL;
    }
    result = (*env)->NewObjectArray(env, size, byte_array_cls, NULL);
    if (result == NULL) {
	return NULL;
    }
    for (ai = res, i = 0; ai != NULL; ai = ai->ai_next, i++) {
	struct sockaddr_in6 *addr = (struct sockaddr_in6 *) ai->ai_addr;
	jbyteArray arr =
	    (*env)->NewByteArray(env, sizeof addr->sin6_addr.s6_addr);
	if (arr == NULL) {
	    return NULL;
	}
	(*env)->SetByteArrayRegion(env, arr, 0, sizeof addr->sin6_addr.s6_addr,
				   (jbyte *) addr->sin6_addr.s6_addr);
	(*env)->SetObjectArrayElement(env, result, i, arr);
	(*env)->DeleteLocalRef(env, arr);
    }
    return result;
}
