/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

#include "jip_HipAddress.h"

#include <stddef.h>
#include <string.h>
#include <netdb.h>

/*
 * Temporarily declare them here while waiting for them to get into
 * the proper headers.
 */
int load_hip_endpoint_pem (const char *, struct endpoint **);
/*
int getmyeidinfo (const struct sockaddr_eid *, struct endpoint **,
		  struct if_nameindex **);
int getpeereidinfo (const struct sockaddr_eid *, struct endpoint **,
		    struct addrinfo **);
*/

static jfieldID value_id;
static jmethodID init_id;

JNIEXPORT void JNICALL
Java_jip_HipAddress_nativeInit (JNIEnv *env, jclass cls)
{
    puts("HipAddress.nativeInit");
    fflush(stdout);
    value_id = (*env)->GetFieldID(env, cls, "value", "S");
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
    printf("flags: %d\n", hints.ei_flags);
    fflush(stdout);
    error = getendpointinfo(khost, kport, &hints, &res);
    printf("Called, error=%d\n", error);
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

JNIEXPORT jobject JNICALL
Java_jip_HipAddress_getOwnFromFile (JNIEnv *env, jclass cls, jstring file)
{
    const jbyte *s = (*env)->GetStringUTFChars(env, file, NULL);
    struct endpoint *endpoint;
    struct sockaddr_eid my_eid;
    int err = load_hip_endpoint_pem(s, &endpoint);
    if (err) {
	jclass io_ex_cls = (*env)->FindClass(env, "java/io/IOException");
	if (io_ex_cls != NULL) {
	    char buffer[256];
	    snprintf(buffer, sizeof buffer,
		     "Could not load endpoint from file %s", s);
	    (*env)->ThrowNew(env, io_ex_cls, buffer);
	}
	return NULL;
    }
    (*env)->ReleaseStringUTFChars(env, file, s);
    err = setmyeid(&my_eid, "", endpoint, NULL);
    if (err) {
	jclass io_ex_cls = (*env)->FindClass(env, "java/io/IOException");
	if (io_ex_cls != NULL) {
	    (*env)->ThrowNew(env, io_ex_cls, "Could not set my EID");
	}
	return NULL;
    }
    return (*env)->NewObject(env, cls, init_id, my_eid.eid_val);
}

JNIEXPORT jobject JNICALL
Java_jip_HipAddress_getPeerFromFile (JNIEnv *env, jclass cls, jstring file,
				     jstring host)
{
    const jbyte *s = (*env)->GetStringUTFChars(env, file, NULL);
    const jbyte *h;
    struct addrinfo hints, *res;
    struct endpoint *endpoint;
    struct sockaddr_eid peer_eid;
    int err = load_hip_endpoint_pem(s, &endpoint);
    if (err) {
	jclass io_ex_cls = (*env)->FindClass(env, "java/io/IOException");
	if (io_ex_cls != NULL) {
	    char buffer[256];
	    snprintf(buffer, sizeof buffer,
		     "Could not load endpoint from file %s", s);
	    (*env)->ThrowNew(env, io_ex_cls, buffer);
	}
	return NULL;
    }
    (*env)->ReleaseStringUTFChars(env, file, s);
    h = (*env)->GetStringUTFChars(env, host, NULL);
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(h, NULL, &hints, &res);
    if (err) {
	char buffer[256];
	jclass uh_ex_cls =
	    (*env)->FindClass(env, "java/net/UnknownHostException");
	snprintf(buffer, sizeof buffer, "Getendpointinfo failed %d: %s", err,
		 gai_strerror(err));
	if (uh_ex_cls != NULL) {
	    (*env)->ThrowNew(env, uh_ex_cls, buffer);
	}
	return NULL;
    }
    err = setpeereid(&peer_eid, "", endpoint, res);
    if (err) {
	jclass io_ex_cls = (*env)->FindClass(env, "java/io/IOException");
	if (io_ex_cls != NULL) {
	    (*env)->ThrowNew(env, io_ex_cls, "Could not set my EID");
	}
	return NULL;
    }
    return (*env)->NewObject(env, cls, init_id, peer_eid.eid_val);
}

/*
JNIEXPORT jbyteArray JNICALL
Java_jip_HipAddress_getMyHostIdentity (JNIEnv *env, jobject obj)
{
    struct sockaddr_eid my_eid;
    struct endpoint *endpoint;
    struct endpoint_hip *epoint;
    jbyteArray result;
    int err, size;
    my_eid.eid_family = PF_HIP;
    my_eid.eid_port = 0;
    my_eid.eid_val = (*env)->GetShortField(env, obj, value_id);
    err = getmyeidinfo(&my_eid, &endpoint, NULL);
    if (err) {
	jclass io_ex_cls = (*env)->FindClass(env, "java/io/IOException");
	if (io_ex_cls != NULL) {
	    (*env)->ThrowNew(env, io_ex_cls, "Could not get my endpoint");
	}
	return NULL;
    }
    epoint = (struct endpoint_hip *) endpoint;
    size = epoint->length - offsetof(struct endpoint_hip, id);
    result = (*env)->NewByteArray(env, size);
    if (result != NULL) {
	(*env)->SetByteArrayRegion(env, result, 0, size,
				   (jbyte *) &epoint->id);
    }
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_jip_HipAddress_getPeerHostIdentity (JNIEnv *env, jobject obj)
{
    struct sockaddr_eid my_eid;
    struct endpoint *endpoint;
    struct endpoint_hip *epoint;
    jbyteArray result;
    int err, size;
    my_eid.eid_family = PF_HIP;
    my_eid.eid_port = 0;
    my_eid.eid_val = (*env)->GetShortField(env, obj, value_id);
    err = getpeereidinfo(&my_eid, &endpoint, NULL);
    if (err) {
	jclass io_ex_cls = (*env)->FindClass(env, "java/io/IOException");
	if (io_ex_cls != NULL) {
	    (*env)->ThrowNew(env, io_ex_cls, "Could not get my endpoint");
	}
	return NULL;
    }
    epoint = (struct endpoint_hip *) endpoint;
    size = epoint->length - offsetof(struct endpoint_hip, id);
    result = (*env)->NewByteArray(env, size);
    if (result != NULL) {
	(*env)->SetByteArrayRegion(env, result, 0, size,
				   (jbyte *) &epoint->id);
    }
    return result;
}
*/
