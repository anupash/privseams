AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(wildcard *.h)

bin_PROGRAMS = conntest-client-opp \
               conntest-client-hip \
               conntest-client-native \
               conntest-client-native-user-key \
               conntest-server \
               conntest-server-native \
               hipsetup \
               first_test \
               cookietest \
               keygentest \
               hashtest \
               listtest \
               opendhtteststub \
               certteststub \
               sqliteteststub \
               hc_performance \
               auth_performance
               
if HIP_PERFORMANCE
bin_PROGRAMS += dh_performance
endif


conntest_client_opp_SOURCES = conntest-client-opp.c \
                              conntest.c
conntest_client_opp_LDADD = ../libhipcore/.libs/libhipcore.a \
                            ../libhiptool/.libs/libhiptool.a

conntest_client_hip_SOURCES = conntest-client-hip.c \
                              conntest.c
conntest_client_hip_LDADD = ../libhipcore/.libs/libhipcore.a \
                            ../libhiptool/.libs/libhiptool.a

conntest_client_native_SOURCES = conntest-client-native.c \
                                conntest.c
conntest_client_native_LDADD = ../libhipcore/.libs/libhipcore.a \
                               ../libhiptool/.libs/libhiptool.a

conntest_client_native_user_key_SOURCES = conntest-client-native-user-key.c
conntest_client_native_user_key_LDADD = ../libhipcore/.libs/libhipcore.a \
                                        ../libhiptool/.libs/libhiptool.a

conntest_server_SOURCES = conntest-server.c \
                          conntest.c
conntest_server_LDADD = ../libhipcore/.libs/libhipcore.a \
                        ../libhiptool/.libs/libhiptool.a

conntest_server_native_SOURCES = conntest-server-native.c \
                                conntest.c
conntest_server_native_LDADD = ../libhipcore/.libs/libhipcore.a \
                               ../libhiptool/.libs/libhiptool.a

hipsetup_SOURCES = hipsetup.c \
                   misc_install.c \
                   conntest.c
hipsetup_LDADD = ../libhipcore/.libs/libhipcore.a \
                 ../libhiptool/.libs/libhiptool.a \
                 ../libhipconf/.libs/libhipconf.a
if HIP_OPENDHT
hipsetup_LDADD += ../libdht/.libs/libhipopendht.a
endif

first_test_SOURCES = first_test.c \
                     misc_install.c \
                     conntest.c
first_test_LDADD = ../libhipcore/.libs/libhipcore.a \
                   ../libhiptool/.libs/libhiptool.a \
                   ../libhipconf/.libs/libhipconf.a
if HIP_OPENDHT
first_test_LDADD += ../libdht/.libs/libhipopendht.a
endif
                     
cookietest_SOURCES = cookietest.c
cookietest_LDADD = ../libhipcore/.libs/libhipcore.a \
                   ../libhiptool/.libs/libhiptool.a

keygentest_SOURCES = keygentest.c
keygentest_LDADD = ../libhipcore/.libs/libhipcore.a \
                   ../libhiptool/.libs/libhiptool.a

hashtest_SOURCES = hashtest.c
hashtest_LDADD = ../libhipcore/.libs/libhipcore.a \
                 ../libhiptool/.libs/libhiptool.a

listtest_SOURCES = listtest.c

opendhtteststub_SOURCES = opendhtteststub.c
opendhtteststub_LDADD = ../libhipcore/.libs/libhipcore.a \
                        ../libhiptool/.libs/libhiptool.a \
                        ../libdht/.libs/libhipopendht.a

certteststub_SOURCES = certteststub.c
certteststub_LDADD = ../libhipcore/.libs/libhipcore.a \
                     ../libhiptool/.libs/libhiptool.a

sqliteteststub_SOURCES = sqliteteststub.c
sqliteteststub_LDADD = ../libhipcore/.libs/libhipcore.a \
                       ../libhiptool/.libs/libhiptool.a

hc_performance_SOURCES = hc_performance.c
hc_performance_LDADD = ../libhipcore/.libs/libhipcore.a \
                       ../libhiptool/.libs/libhiptool.a

auth_performance_SOURCES = auth_performance.c
auth_performance_LDADD = ../libhipcore/.libs/libhipcore.a \
                         ../libhiptool/.libs/libhiptool.a

if HIP_PERFORMANCE
dh_performance_SOURCES = dh_performance.c
dh_performance_LDADD = ../libhipcore/.libs/libhipcore.a \
                       ../libhiptool/.libs/libhiptool.a
endif
