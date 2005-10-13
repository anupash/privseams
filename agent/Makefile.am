AUTOMAKE_OPTIONS = foreign

# Specify HIPL topdir manually. top_srcdir may not work otherwise if configure
# is invoked manually directly in this dir. The global include file uses the
# HIPL variable to setup some HIPL_* variables.
# 
HIPL = $(PWD)/..
include $(HIPL)/Makefile.am.global

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
CFLAGS = -DHIP_LOGFMT_LONG -g -DCONFIG_HIP_DEBUG -DCONFIG_HIP_USERSPACE
CFLAGS += -DCONFIG_HIP_AGENT -DCONFIG_HIPGUI_COMMANDLINE

include_HEADERS = crypto.h netlink.h
INCLUDES = -I$(HIPL_LINUX_INCLUDE) -I$(PWD) -I$(HIPL_LIBINET6_INCLUDE)
INCLUDES += -I$(HIPL_LIBINET6) -I$(HIPL_LINUX_MODULE) -I$(HIPL) -I$(HIPL_HIPD)

sbin_PROGRAMS = agent
agent_SOURCES = agent.c agent_tools.c connhipd.c gui_interface.c hit_db.c

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below
agent_LDADD = ../libinet6/.libs/libinet6.a
agent_LDFLAGS = -lcrypto -lpthread

SUBDIRS =

# The sources depend on builder, but it is located elsewhere. Linking is
# the best way to access it because the object must be built on this
# directory and we don't want to make reduntant copies.
#
builder.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/builder.h .
builder.c: builder.h
	$(LN_S) -f $(HIPL_LINUX_MODULE)/builder.c .
crypto.c: crypto.h
crypto.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/crypto.h .
netlink.h:
	$(LN_S) -f $(HIPL_LINUX_MODULE)/netlink.h .

tags:
	etags $(hipd_SOURCES) $(include_HEADERS)

