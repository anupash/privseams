AUTOMAKE_OPTIONS = foreign

# Specify HIPL topdir manually. top_srcdir may not work otherwise if configure
# is invoked manually directly in this dir. The global include file uses the
# HIPL variable to setup some HIPL_* variables.
# 
HIPL = $(PWD)/..
include $(HIPL)/Makefile.am.global

# Note: HIPL is included because "libinet6/debug.h" is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
#
CFLAGS += -I$(HIPL_TOOLS) -I$(HIPL_LIBINET6_INCLUDE) -I$(HIPL)
CFLAGS += -I$(HIPL_LINUX_INCLUDE) -I$(HIPL_LINUX_MODULE)
CFLAGS += -DHIP_UNITTEST_MODE -DCONFIG_HIP_DEBUG -DHIP_LOGFMT_LONG -g
CFLAGS += -L$(HIPL_LIBINET6_LIB)

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below
LDADD  = ../libinet6/.libs/libinet6.a

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
conntest_client_SOURCES = conntest-client.c 
conntest_client_gai_SOURCES = conntest-client-gai.c
conntest_client_native_SOURCES = conntest-client-native.c
conntest_client_native_user_key_SOURCES = \
                        conntest-client-native-user-key.c
conntest_server_native_SOURCES = conntest-server-native.c
conntest_server_SOURCES = conntest-server.c
libinet6test_SOURCES = libinet6test.c
listifaces_SOURCES = listifaces.c
unittest_SOURCES = unit.c unittest.c unittest.h hipconf.c suite.c

# The sources depend on FILE.c, but it is located elsewhere. Linking is
# the probably the best way to access it because the object must be built
# on this directory and we do't want to make reduntant copies.
#
hipconf.h:
	$(LN_S) -f $(HIPL_TOOLS)/hipconf.h .
hipconf.c: hipconf.h
	$(LN_S) -f $(HIPL_TOOLS)/hipconf.c .
unit.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/unit.h .
unit.c: unit.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/unit.c .
$(HIPL_LIBINET6_LIB_STATIC):
	$(MAKE) -C $(HIPL)/libinet6
