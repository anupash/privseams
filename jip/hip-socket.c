/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

#include "jip_HipSocket.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#define CHECKINT(oper, message, text) do \
    if ((oper) < 0) { \
	jclass io_ex_cls = (*env)->FindClass(env, "java/io/IOException"); \
	if (io_ex_cls != NULL) { \
            char buffer[256]; \
            sprintf(buffer, "%s: %s", message, strerror(errno)); \
	    (*env)->ThrowNew(env, io_ex_cls, buffer); \
            text; \
	} \
    } while (0)

#define CHECK(oper, message) CHECKINT(oper, message, return)
#define CHECKVAL(oper, message, value) CHECKINT(oper, message, return value)

#define DEFINE_CONSTANT(name) do { \
    jfieldID fid = (*env)->GetStaticFieldID(env, cls, #name, "I"); \
    JAVA_##name = (*env)->GetStaticIntField(env, cls, fid); \
    } while (0)

static jfieldID native_fd_id;
static jfieldID localport_id;
static jfieldID port_id;
static jmethodID dump_id;
static jmethodID set_address_id;
static jmethodID ia_get_host_address_id;

static jint JAVA_IP_MULTICAST_IF;
static jint JAVA_IP_MULTICAST_IF2;
static jint JAVA_IP_MULTICAST_LOOP;
static jint JAVA_IP_TOS;
static jint JAVA_SO_BINDADDR;
static jint JAVA_SO_BROADCAST;
static jint JAVA_SO_KEEPALIVE;
static jint JAVA_SO_LINGER;
static jint JAVA_SO_OOBINLINE;
static jint JAVA_SO_RCVBUF;
static jint JAVA_SO_REUSEADDR;
static jint JAVA_SO_SNDBUF;
static jint JAVA_SO_TIMEOUT;
static jint JAVA_TCP_NODELAY;

static int
get_boolean (JNIEnv *env, jobject obj)
{
    int result = -1;
    jclass cls = (*env)->GetObjectClass(env, obj);
    if (cls != NULL) {
	jmethodID mid = (*env)->GetMethodID(env, cls, "booleanValue", "()Z");
	if (mid != NULL) {
	    result = (*env)->CallBooleanMethod(env, obj, mid);
	    if ((*env)->ExceptionOccurred(env)) {
		result = -1;
	    }
	}
    }
    return result;
}

static int
get_integer (JNIEnv *env, jobject obj)
{
    int result = -1;
    jclass cls = (*env)->GetObjectClass(env, obj);
    if (cls != NULL) {
	jmethodID mid = (*env)->GetMethodID(env, cls, "intValue", "()I");
	if (mid != NULL) {
	    result = (*env)->CallIntMethod(env, obj, mid);
	    if ((*env)->ExceptionOccurred(env)) {
		result = -1;
	    }
	}
    }
    return result;
}

static jobject
create_boolean (JNIEnv *env, jboolean value)
{
    jobject result = NULL;
    jclass cls = (*env)->FindClass(env, "java/lang/Boolean");
    if (cls != NULL) {
	jmethodID mid = (*env)->GetMethodID(env, cls, "<init>", "(Z)V");
	if (mid != NULL) {
	    result = (*env)->NewObject(env, cls, mid, value);
	}
    }
    return result;
}

static jobject
create_integer (JNIEnv *env, jint value)
{
    jobject result = NULL;
    jclass cls = (*env)->FindClass(env, "java/lang/Integer");
    if (cls != NULL) {
	jmethodID mid = (*env)->GetMethodID(env, cls, "<init>", "(I)V");
	if (mid != NULL) {
	    result = (*env)->NewObject(env, cls, mid, value);
	}
    }
    return result;
}

JNIEXPORT void JNICALL
Java_jip_HipSocket_nativeInit (JNIEnv *env, jclass cls)
{
    jclass ia_cls = (*env)->FindClass(env, "java/net/InetAddress");
    if (ia_cls == NULL) {
	return;
    }
    puts("Native init");
    fflush(stdout);
    native_fd_id = (*env)->GetFieldID(env, cls, "native_fd", "I");
    localport_id = (*env)->GetFieldID(env, cls, "localport", "I");
    port_id = (*env)->GetFieldID(env, cls, "port", "I");
    dump_id = (*env)->GetMethodID(env, cls, "dump", "()V");
    set_address_id = (*env)->GetMethodID(env, cls, "setAddress", "([B)V");
    ia_get_host_address_id = (*env)->GetMethodID(env, ia_cls, "getHostAddress",
						 "()Ljava/lang/String;");
    DEFINE_CONSTANT(IP_MULTICAST_IF);
    DEFINE_CONSTANT(IP_MULTICAST_IF2);
    DEFINE_CONSTANT(IP_MULTICAST_LOOP);
    DEFINE_CONSTANT(IP_TOS);
    DEFINE_CONSTANT(SO_BINDADDR);
    DEFINE_CONSTANT(SO_BROADCAST);
    DEFINE_CONSTANT(SO_KEEPALIVE);
    DEFINE_CONSTANT(SO_LINGER);
    DEFINE_CONSTANT(SO_OOBINLINE);
    DEFINE_CONSTANT(SO_RCVBUF);
    DEFINE_CONSTANT(SO_REUSEADDR);
    DEFINE_CONSTANT(SO_SNDBUF);
    DEFINE_CONSTANT(SO_TIMEOUT);
    DEFINE_CONSTANT(TCP_NODELAY);
}

JNIEXPORT void JNICALL
Java_jip_HipSocket_bind (JNIEnv *env, jobject obj, jobject addr, jint port)
{
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    jstring addr_str = (*env)->CallObjectMethod(env, addr,
						ia_get_host_address_id);
    const jbyte *s = (*env)->GetStringUTFChars(env, addr_str, NULL);
    struct addrinfo hints, *res, *ai;
    char buffer[256];
    int error, i;
    snprintf(buffer, sizeof buffer, "%d", port);
    printf("Bind: <%s:%d> %d\n", s, port, fd);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_HIP;
    error = getaddrinfo(s, buffer, &hints, &res);
    if (error) {
	char buf[256];
	snprintf(buf, sizeof buf, "Getaddrinfo failed %d: %s", error,
		 gai_strerror(error));
	CHECK(-1, buf);
    }
    (*env)->ReleaseStringUTFChars(env, addr_str, s);
    printf("got gai addresses:\n");
    for(ai = res; ai != NULL; ai = ai->ai_next) {
      struct sockaddr_in6 *s = (struct sockaddr_in6 *)ai->ai_addr;

      //s->sin6_port = htons(port);
	printf("GAI: ai_flags=%d ai_family=%d ai_socktype=%d ai_protocol=%d ai_addrlen=%d ai_canonname=%s\n",
	       ai->ai_flags, ai->ai_family, ai->ai_socktype, ai->ai_protocol, ai->ai_addrlen, ai->ai_canonname);
	printf("\tAF_INET6: ship6_port=%d in6_addr=0x", port);
	for (i = 0; i < 16; i++) printf("%02x", (unsigned char) (s->sin6_addr.in6_u.u6_addr8[i]));
	printf("\n");
    }
    printf("\n\n");
    ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr = in6addr_any;
    CHECK(bind(fd, res->ai_addr, res->ai_addrlen), "Bind failed");
    (*env)->SetIntField(env, obj, localport_id, port);
}

JNIEXPORT void JNICALL
Java_jip_HipSocket_create (JNIEnv *env, jobject obj, jboolean is_stream)
{
    int fd = socket(AF_INET6, is_stream ? SOCK_STREAM : SOCK_DGRAM, 0);
    printf("Create: %d %d\n", fd, is_stream);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    CHECK(fd, "Cannot create socket");
    (*env)->SetIntField(env, obj, native_fd_id, fd);
}

JNIEXPORT void JNICALL
Java_jip_HipSocket_connect (JNIEnv *env, jobject obj, jobject address,
			    jint port)
{
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    jstring addr_str = (*env)->CallObjectMethod(env, address,
						ia_get_host_address_id);
    const jbyte *s = (*env)->GetStringUTFChars(env, addr_str, NULL);
    struct addrinfo hints, *res, *ai;
    struct sockaddr_in6 addr;
    jbyteArray addr_bytes;
    char buffer[256];
    int error, i;
    snprintf(buffer, sizeof buffer, "%d", port);
    printf("Connect: <%s:%d> %d\n", s, port, fd);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_HIP;
    error = getaddrinfo(s, buffer, &hints, &res);
    if (error) {
	char buf[256];
	snprintf(buf, sizeof buf, "Getaddrinfo failed %d: %s", error,
		 gai_strerror(error));
	CHECK(-1, buf);
    }
    (*env)->ReleaseStringUTFChars(env, addr_str, s);
    printf("got gai addresses:\n");
    for(ai = res; ai != NULL; ai = ai->ai_next) {
	struct sockaddr_in6 *s = (struct sockaddr_in6 *)ai->ai_addr;
	int i = 0;

	//s->sin6_port = htons(port);
	printf("GAI: ai_flags=%d ai_family=%d ai_socktype=%d ai_protocol=%d ai_addrlen=%d ai_canonname=%s\n",
	       ai->ai_flags, ai->ai_family, ai->ai_socktype, ai->ai_protocol, ai->ai_addrlen, ai->ai_canonname);
	printf("\tAF_INET6: ship6_port=%d in6_addr=0x", port);
	for (i = 0; i < 16; i++) printf("%02x", (unsigned char) (s->sin6_addr.in6_u.u6_addr8[i]));
	printf("\n");
    }
    printf("\n\n");
    CHECK(connect(fd, res->ai_addr, res->ai_addrlen), "Connect failed");
    (*env)->SetIntField(env, obj, port_id, port);
    memset(&addr, 0, sizeof addr);
    memcpy(&addr, res->ai_addr, res->ai_addrlen);
    for (i = 0; i < 16; i++) printf("%02x", (unsigned char) (addr.sin6_addr.in6_u.u6_addr8[i]));
    printf("\n");
    addr_bytes = (*env)->NewByteArray(env, sizeof addr.sin6_addr.s6_addr);
    (*env)->SetByteArrayRegion(env, addr_bytes, 0,
			       sizeof addr.sin6_addr.s6_addr,
			       (jbyte *) addr.sin6_addr.s6_addr);
    (*env)->CallVoidMethod(env, obj, set_address_id, addr_bytes);
}

JNIEXPORT void JNICALL
Java_jip_HipSocket_listen (JNIEnv *env, jobject obj, jint backlog)
{
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    printf("Listen: %d %d\n", fd, backlog);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    CHECK(listen(fd, backlog), "Listen failed");
}

JNIEXPORT void JNICALL
Java_jip_HipSocket_accept (JNIEnv *env, jobject obj, jobject impl)
{
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    int s;
    struct sockaddr_in6 local_addr, remote_addr;
    socklen_t local_len = sizeof local_addr, remote_len = sizeof remote_addr;
    jbyteArray remote_bytes;
    printf("Accept: %d\n", fd);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    s = accept(fd, NULL, NULL);
    CHECK(s, "Accept failed");
    CHECK(getsockname(s, (struct sockaddr *) &local_addr, &local_len),
	  "Sockname failed");
    CHECK(getpeername(s, (struct sockaddr *) &remote_addr, &remote_len),
	  "Peername failed");
    (*env)->SetIntField(env, impl, native_fd_id, s);
    (*env)->SetIntField(env, impl, localport_id, ntohs(local_addr.sin6_port));
    (*env)->SetIntField(env, impl, port_id, ntohs(remote_addr.sin6_port));
    remote_bytes = (*env)->NewByteArray(env,
					sizeof remote_addr.sin6_addr.s6_addr);
    (*env)->SetByteArrayRegion(env, remote_bytes, 0,
			       sizeof remote_addr.sin6_addr.s6_addr,
			       (jbyte *) remote_addr.sin6_addr.s6_addr);
    (*env)->CallVoidMethod(env, impl, set_address_id, remote_bytes);
}

JNIEXPORT jint JNICALL
Java_jip_HipSocket_available (JNIEnv *env, jobject obj)
{
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    int value;
    printf("Available: %d\n", fd);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    CHECKVAL(ioctl(fd, FIONREAD, &value), "Available failed", -1);
    return value;
}

JNIEXPORT void JNICALL
Java_jip_HipSocket_close (JNIEnv *env, jobject obj)
{
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    printf("Close: %d\n", fd);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    CHECK(close(fd), "Close failed");
}

JNIEXPORT void JNICALL
Java_jip_HipSocket_sendUrgentData (JNIEnv *env, jobject obj, jint data)
{
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    char c = data & 0xFF;
    printf("Urgent: %d %d\n", fd, data);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    CHECK(send(fd, &c, 1, MSG_OOB), "Urgent failed");
}

JNIEXPORT jobject JNICALL
Java_jip_HipSocket_getOption (JNIEnv *env, jobject obj, jint id)
{
    jobject result = NULL;
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    printf("Get option: %d %d\n", fd, id);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    if (id == JAVA_TCP_NODELAY) {
	int optval;
	int optlen = sizeof optval;
	CHECKVAL(getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &optval, &optlen),
		 "Get option failed", NULL);
	if (optval) {
	    result = create_boolean(env, JNI_TRUE);
	} else {
	    result = create_boolean(env, JNI_FALSE);
	}
    } else if (id == JAVA_SO_TIMEOUT) {
	struct timeval optval;
	int optlen = sizeof optval;
	CHECKVAL(getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &optval, &optlen),
		 "Get option failed", NULL);
	result = create_integer(env, optval.tv_sec * 1000
				+ optval.tv_usec / 1000);
    } else {
	jclass ex_cls = (*env)->FindClass(env, "java/net/SocketException");
	if (ex_cls != NULL) {
	    char buffer[256];
	    sprintf(buffer, "Unrecognized option: %d", id);
	    (*env)->ThrowNew(env, ex_cls, buffer);
	}
    }
    return result;
}

JNIEXPORT void JNICALL
Java_jip_HipSocket_setOption (JNIEnv *env, jobject obj, jint id, jobject value)
{
    int fd = (*env)->GetIntField(env, obj, native_fd_id);
    printf("Set option: %d %d\n", fd, id);
    fflush(stdout);
    (*env)->CallVoidMethod(env, obj, dump_id);
    if (id == JAVA_TCP_NODELAY) {
	int optval = get_boolean(env, value);
	if (optval == -1) {
	    return;
	}
	CHECK(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof optval),
	      "Set option failed");
    } else if (id == JAVA_SO_TIMEOUT) {
	int time = get_integer(env, value);
	struct timeval optval;
	if (time == -1) {
	    return;
	}
	optval.tv_sec = time / 1000;
	optval.tv_usec = time % 1000;
	CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &optval, sizeof optval),
	      "Set option failed");
    } else {
	jclass ex_cls = (*env)->FindClass(env, "java/net/SocketException");
	if (ex_cls != NULL) {
	    char buffer[256];
	    sprintf(buffer, "Unrecognized option: %d", id);
	    (*env)->ThrowNew(env, ex_cls, buffer);
	}
    }
}
