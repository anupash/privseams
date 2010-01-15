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
conntest_client_opp_LDADD = ../libhipcore/libhipcore.la \
                            ../libhiptool/libhiptool.la
if HIP_PERFORMANCE
conntest_client_opp_LDADD += ../performance/libperformance.la
endif

conntest_client_hip_SOURCES = conntest-client-hip.c \
                              conntest.c
conntest_client_hip_LDADD = ../libhipcore/libhipcore.la \
                            ../libhiptool/libhiptool.la
if HIP_PERFORMANCE
conntest_client_hip_LDADD += ../performance/libperformance.la
endif

conntest_client_native_SOURCES = conntest-client-native.c \
                                conntest.c
conntest_client_native_LDADD = ../libhipcore/libhipcore.la \
                               ../libhiptool/libhiptool.la
if HIP_PERFORMANCE
conntest_client_native_LDADD += ../performance/libperformance.la
endif

conntest_client_native_user_key_SOURCES = conntest-client-native-user-key.c
conntest_client_native_user_key_LDADD = ../libhipcore/libhipcore.la \
                                        ../libhiptool/libhiptool.la
if HIP_PERFORMANCE
conntest_client_native_user_key_LDADD += ../performance/libperformance.la
endif

conntest_server_SOURCES = conntest-server.c \
                          conntest.c
conntest_server_LDADD = ../libhipcore/libhipcore.la \
                        ../libhiptool/libhiptool.la
if HIP_PERFORMANCE
conntest_server_LDADD += ../performance/libperformance.la
endif

conntest_server_native_SOURCES = conntest-server-native.c \
                                conntest.c
conntest_server_native_LDADD = ../libhipcore/libhipcore.la \
                               ../libhiptool/libhiptool.la
if HIP_PERFORMANCE
conntest_server_native_LDADD += ../performance/libperformance.la
endif

hipsetup_SOURCES = hipsetup.c \
                   misc_install.c \
                   conntest.c
hipsetup_LDADD = ../libhipcore/libhipcore.la \
                 ../libhiptool/libhiptool.la \
                 ../libhipconf/libhipconf.la
if HIP_DHT
hipsetup_LDADD += ../libdht/libhipopendht.la
endif

if HIP_PERFORMANCE
hipsetup_LDADD += ../performance/libperformance.la
endif

first_test_SOURCES = first_test.c \
                     misc_install.c \
                     conntest.c
first_test_LDADD = ../libhipcore/libhipcore.la \
                   ../libhiptool/libhiptool.la \
                   ../libhipconf/libhipconf.la
if HIP_DHT
first_test_LDADD += ../libdht/libhipopendht.la
endif

if HIP_PERFORMANCE
first_test_LDADD += ../performance/libperformance.la
endif
                     
cookietest_SOURCES = cookietest.c
cookietest_LDADD = ../libhipcore/libhipcore.la \
                   ../libhiptool/libhiptool.la
if HIP_PERFORMANCE
cookietest_LDADD += ../performance/libperformance.la
endif
                   
keygentest_SOURCES = keygentest.c
keygentest_LDADD = ../libhipcore/libhipcore.la \
                   ../libhiptool/libhiptool.la
                   
if HIP_PERFORMANCE
keygentest_LDADD += ../performance/libperformance.la
endif

hashtest_SOURCES = hashtest.c
hashtest_LDADD = ../libhipcore/libhipcore.la \
                 ../libhiptool/libhiptool.la

if HIP_PERFORMANCE
hashtest_LDADD += ../performance/libperformance.la
endif

listtest_SOURCES = listtest.c

opendhtteststub_SOURCES = opendhtteststub.c
opendhtteststub_LDADD = ../libhipcore/libhipcore.la \
                        ../libhiptool/libhiptool.la \
                        ../libdht/libhipopendht.la
                        
if HIP_PERFORMANCE
opendhtteststub_LDADD += ../performance/libperformance.la
endif

certteststub_SOURCES = certteststub.c
certteststub_LDADD = ../libhipcore/libhipcore.la \
                     ../libhiptool/libhiptool.la
                     
if HIP_PERFORMANCE
certteststub_LDADD += ../performance/libperformance.la
endif
                     
sqliteteststub_SOURCES = sqliteteststub.c
sqliteteststub_LDADD = ../libhipcore/libhipcore.la \
                       ../libhiptool/libhiptool.la
                       
if HIP_PERFORMANCE
sqliteteststub_LDADD += ../performance/libperformance.la
endif

hc_performance_SOURCES = hc_performance.c
hc_performance_LDADD = ../libhipcore/libhipcore.la \
                       ../libhiptool/libhiptool.la

if HIP_PERFORMANCE
hc_performance_LDADD += ../performance/libperformance.la
endif

auth_performance_SOURCES = auth_performance.c
auth_performance_LDADD = ../libhipcore/libhipcore.la \
                         ../libhiptool/libhiptool.la
                         
if HIP_PERFORMANCE
auth_performance_LDADD += ../performance/libperformance.la
endif
          
if HIP_PERFORMANCE
dh_performance_SOURCES = dh_performance.c
dh_performance_LDADD = ../libhipcore/libhipcore.la \
                       ../libhiptool/libhiptool.la \
                       ../performance/libperformance.la
endif
