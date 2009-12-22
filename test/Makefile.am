AUTOMAKE_OPTIONS = foreign

CFLAGS = $(hipl_common_cflags) -L$(HIPL_LIBINET6_LIB) $(HIPL_XMLL)

EXTRA_DIST = $(wildcard *.h)

INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)  -I$(HIPL_PJPROJECT_NATH)/include -I$(HIPL_PJPROJECT_LIB)/include -I$(HIPL_PJPROJECT_LIB_UTIL)/include -I$(HIPL_PJPROJECT_MEDIA)/include

bin_PROGRAMS = conntest-client-opp \
               conntest-client-hip \
               conntest-client-native \
               conntest-client-native-user-key \
               conntest-server \
               conntest-server-native \
               hipsetup \
               listifaces \
               first_test \
               cookietest \
               keygentest \
               hashtest \
               listtest \
               opendhtteststub \
               certteststub \
               sqliteteststub \
               hc_performance \
               auth_performance \
               load
               
if HIP_PERFORMANCE
bin_PROGRAMS += dh_performance
endif


conntest_client_opp_SOURCES = conntest-client-opp.c \
                              conntest.c

conntest_client_hip_SOURCES = conntest-client-hip.c \
                              conntest.c

conntest_client_native_SOURCES = conntest-client-native.c \
                                conntest.c
                                
conntest_client_native_user_key_SOURCES = conntest-client-native-user-key.c

conntest_server_SOURCES = conntest-server.c \
                          conntest.c

conntest_server_native_SOURCES = conntest-server-native.c \
                                conntest.c
                              
conntest_client_opp_LDADD = ../libhipcore/.libs/libhipcore.a \
                            ../libhiptool/.libs/libhiptool.a

conntest_client_hip_LDADD = ../libhipcore/.libs/libhipcore.a \
                            ../libhiptool/.libs/libhiptool.a

conntest_client_native_LDADD = ../libhipcore/.libs/libhipcore.a \
                               ../libhiptool/.libs/libhiptool.a

conntest_client_native_user_key_LDADD = ../libhipcore/.libs/libhipcore.a \
                                        ../libhiptool/.libs/libhiptool.a

conntest_server_LDADD = ../libhipcore/.libs/libhipcore.a \
                        ../libhiptool/.libs/libhiptool.a

conntest_server_native_LDADD = ../libhipcore/.libs/libhipcore.a \
                               ../libhiptool/.libs/libhiptool.a


opendhtteststub_LDFLAGS = -lcrypto $(HIP_XMLL) 
opendhtteststub_LDADD = 

opendhtteststub_LDADD += ../libhipcore/.libs/libhipcore.a
if HIP_LIBINET6
opendhtteststub_LDADD += ../libinet6/.libs/libinet6.a
endif
opendhtteststub_LDADD += ../libhiptool/.libs/libhiptool.a
opendhtteststub_LDADD += ../libdht/.libs/libhipopendht.a

if HIP_PERFORMANCE
opendhtteststub_LDADD += ../performance/.libs/libperformance.a
endif

LDADD = ../libhipcore/.libs/libhipcore.a
if HIP_LIBINET6
LDADD += ../libinet6/.libs/libinet6.a
endif
LDADD += ../libhiptool/.libs/libhiptool.a
LDADD += ../libhipconf/.libs/libhipconf.a

if HIP_OPENDHT
LDADD += ../libdht/.libs/libhipopendht.a
endif

LDFLAGS = @LDFLAGS@ -L$(HIPL_LIBINET6_LIB) -L$(HIPL_LIBHIPTOOL_LIB) -L$(HIPL_LIBHIPCORE_LIB) -L$(HIPL_OPENDHT_LIB) 
LDFLAGS += -L$(HIPL_LIBHIPCONF_LIB)

if HIP_OPENWRT
LDFLAGS += $(OPENWRT)
endif

if HIP_PERFORMANCE
LDADD += ../performance/.libs/libperformance.a
endif

hipsetup_SOURCES = hipsetup.c misc_install.c conntest.c
first_test_SOURCES = first_test.c misc_install.c conntest.c
cookietest_SOURCES = cookietest.c
keygentest_SOURCES = keygentest.c
hashtest_SOURCES = hashtest.c
listtest_SOURCES = listtest.c
opendhtteststub_SOURCES = opendhtteststub.c
certteststub_SOURCES = certteststub.c
sqliteteststub_SOURCES = sqliteteststub.c
if HIP_PERFORMANCE
dh_performance_SOURCES = dh_performance.c
endif
hc_performance_SOURCES = hc_performance.c
auth_performance_SOURCES = auth_performance.c
load_SOURCES = load.c
