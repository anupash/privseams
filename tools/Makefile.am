AUTOMAKE_OPTIONS = foreign

# Note: -I.. is included because tools/debug.h" is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
#
CFLAGS += -I../libinet6/include -I../linux/include -I../linux/net/ipv6/hip -I..
CFLAGS += -DCONFIG_HIP_DEBUG -DHIP_LOGFMT_LONG -g

bin_PROGRAMS = hipconf

hipconf_SOURCES = hipconf.c debug.c builder.h builder.c message.c crypto.c

# The sources depend on builder, but it is located elsewhere. Linking is
# probably the best way to access it because the object must be built on
# this directory and we don't want to make reduntant copies.
#
builder.c:
	$(LN_S) -f ../linux/net/ipv6/hip/builder.c .
