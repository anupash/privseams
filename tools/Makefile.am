AUTOMAKE_OPTIONS = foreign

# Note: .. is included because tools/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
# The ../libinet6/include_glibc23 is included because the ../libinet6/include
# path may not exist (it is created by libinet6/configure).
#
CFLAGS += -I../libinet6/include -I../libinet6/include_glibc23
CFLAGS += -I../linux/include -I../linux/net/ipv6/hip -I..
CFLAGS += -DCONFIG_HIP_DEBUG -DHIP_LOGFMT_LONG -g

bin_PROGRAMS = hipconf

hipconf_SOURCES = hipconf.c debug.c builder.h builder.c message.c crypto.c

# The sources depend on builder, but it is located elsewhere. Linking is
# probably the best way to access it because the object must be built on
# this directory and we don't want to make reduntant copies.
#
builder.c:
	$(LN_S) -f ../linux/net/ipv6/hip/builder.c .
