AUTOMAKE_OPTIONS = foreign

# Note: HIPL is included because "libinet6/debug.h" is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
#
CFLAGS = $(hipl_common_cflags) -DHIP_UNITTEST_MODE -L$(HIPL_LIBINET6_LIB)

include_HEADERS = checksum.h first_test.h hipsetup.h start-stop-daemon.h
include_HEADERS += unittest.h conntest.h hipconftool.h misc_install.h unit.h

INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)

conntest_client_LDADD = 
if HIP_OPPORTUNISTIC
  # currently opp. library does not work with conntest-client-gai
  conntest_client_LDADD += ../libopphip/.libs/libopphip.a
endif

conntest_client_LDADD += ../libinet6/.libs/libinet6.a
hashtest_LDADD = ../libinet6/.libs/libinet6.a
listtest_LDADD =

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below
# Note: libhiptool needs to be the last library in LDADD!!
#
LDADD  = ../libinet6/.libs/libinet6.a

if HIP_CORPORATE
  conntest_client_LDADD += -lhiptool
  hashtest_LDADD += -lhiptool
  LDADD += -lhiptool
else
  conntest_client_LDADD += ../libhiptool/.libs/libhiptool.a
  hashtest_LDADD += ../libhiptool/.libs/libhiptool.a
  LDADD += ../libhiptool/.libs/libhiptool.a
endif

if HIP_OPENDHT
  conntest_client_LDADD += ../opendht/.libs/libhipopendht.a
  LDADD += ../opendht/.libs/libhipopendht.a
  CFLAGS += $(HIPL_XMLL)
endif

bin_PROGRAMS = conntest-client
bin_PROGRAMS += conntest-server
bin_PROGRAMS += conntest-client-gai
bin_PROGRAMS += conntest-client-native
bin_PROGRAMS += conntest-client-native-user-key
bin_PROGRAMS += conntest-server-native
#bin_PROGRAMS += unittest
bin_PROGRAMS += hipsetup
bin_PROGRAMS += libinet6test
bin_PROGRAMS += listifaces
bin_PROGRAMS += first_test
#sbin_PROGRAMS = modtest
bin_PROGRAMS += cookietest
bin_PROGRAMS += keygentest
#bin_PROGRAMS += sha1ime_test
bin_PROGRAMS += ttcp
bin_PROGRAMS += hashtest
#bin_PROGRAMS += hipconf
bin_PROGRAMS += listtest

#sbin_SCRIPTS = hipsetup

ttcp_SOURCES = ttcp.c
conntest_client_SOURCES = conntest-client.c  conntest.c
conntest_client_gai_SOURCES = conntest-client-gai.c conntest.c
conntest_client_native_SOURCES = conntest-client-native.c conntest.c
conntest_client_native_user_key_SOURCES = \
                        conntest-client-native-user-key.c
conntest_server_native_SOURCES = conntest-server-native.c conntest.c
conntest_server_SOURCES = conntest-server.c conntest.c
#unittest_SOURCES = unit.c unittest.c hipconftool.c suite.c
hipsetup_SOURCES = hipsetup.c hipconftool.c misc_install.c conntest.c
first_test_SOURCES = first_test.c hipconftool.c misc_install.c conntest.c
cookietest_SOURCES = cookietest.c
keygentest_SOURCES = keygentest.c
#sha1ime_test_SOURCES = sha1ime_test.c
#second_test_SOURCES = second_test.c hipconftool.c misc_install.c conntest.c
#modtest_SOURCES = modtest.c
hashtest_SOURCES = hashtest.c
#hipconf_SOURCE = hipconftool.c
listtest_SOURCES = listtest.c

#EXTRA_DIST = $(sbin_SCRIPTS)

# The sources depend on FILE.c, but it is located elsewhere. Linking is
# the probably the best way to access it because the object must be built
# on this directory and we do't want to make reduntant copies.
#
hipconftool.h:
	$(LN_S) -f $(HIPL_TOOLS)/hipconftool.h .
hipconftool.c: hipconftool.h
	$(LN_S) -f $(HIPL_TOOLS)/hipconftool.c .
$(HIPL_LIBINET6_LIB_STATIC):
	$(MAKE) -C $(HIPL)/libinet6


