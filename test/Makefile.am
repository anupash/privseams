AUTOMAKE_OPTIONS = foreign

# Note: -I.. is included because "tools/debug.h" is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
#
CFLAGS += -I../tools -I../libinet6/include -I..
CFLAGS += -I../linux/include -I../linux/net/ipv6/hip
CFLAGS += -DHIP_UNITTEST_MODE -DCONFIG_HIP_DEBUG -DHIP_LOGFMT_LONG -g

bin_PROGRAMS  = align
bin_PROGRAMS += checksum
bin_PROGRAMS += conntest-client
bin_PROGRAMS += conntest-server
bin_PROGRAMS += conntest-client-gai
bin_PROGRAMS += conntest-client-native
bin_PROGRAMS += conntest-client-native-user-key
bin_PROGRAMS += conntest-server-native
bin_PROGRAMS += unittest
bin_PROGRAMS += libinet6test
bin_PROGRAMS += listifaces

align_SOURCES = align.c
checksum_SOURCES = checksum.c checksum.h
conntest_client_SOURCES = conntest-client.c debug.c
conntest_client_gai_SOURCES = conntest-client-gai.c
conntest_client_gai_LDADD = ../libinet6/libinet6.a
conntest_client_native_SOURCES = conntest-client-native.c debug.c
conntest_client_native_LDADD = ../libinet6/libinet6.a
conntest_client_native_user_key_SOURCES = \
                               conntest-client-native-user-key.c debug.c
conntest_client_native_user_key_LDADD = ../libinet6/libinet6.a
conntest_server_native_SOURCES = conntest-server-native.c debug.c
conntest_server_native_LDADD = ../libinet6/libinet6.a
conntest_server_SOURCES = conntest-server.c debug.c
libinet6test_SOURCES = libinet6test.c
libinet6test_LDADD = ../libinet6/libinet6.a
listifaces_SOURCES = listifaces.c debug.c
listifaces_LDADD = ../libinet6/libinet6.a
unittest_SOURCES = unit.c unittest.c unittest.h debug.c hipconf.c \
                   builder.c crypto.c message.c suite.c
unittest_LDADD = -lcrypto

# The sources depend on FILE.c, but it is located elsewhere. Linking is
# the probably the best way to access it because the object must be built
# on this directory and we do't want to make reduntant copies.
#
builder.c:
	$(LN_S) -f ../linux/net/ipv6/hip/builder.c .
crypto.c:
	$(LN_S) -f ../tools/crypto.c .
debug.c:
	$(LN_S) -f ../tools/debug.c .
	$(LN_S) -f ../tools/debug.h .
hipconf.c:
	$(LN_S) -f ../tools/hipconf.c .
	$(LN_S) -f ../tools/hipconf.h .
message.c:
	$(LN_S) -f ../tools/message.c .
unit.c:
	$(LN_S) -f ../linux/net/ipv6/hip/unit.c .
	$(LN_S) -f ../linux/net/ipv6/hip/unit.h .
../libinet6/libinet6.a:
	$(MAKE) -C ../libinet6
