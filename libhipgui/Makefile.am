## Makefile.am for HIP GUI
HIPL = $(PWD)/..
include $(HIPL)/Makefile.am.global

CFLAGS = -O0 $(GDB_CFLAG)

WX_INCLUDES := $(shell wx-config --cxxflags)
WX_CFLAGS := $(shell wx-config --libs)

lib_LTLIBRARIES = libhipgui.la

libhipgui_la_SOURCES = hipagent.cpp hipcontext.cpp hipinterface.cpp hipkey.cpp hippersonality.cpp hiptab.cpp agent_interface.cpp

libhipgui_la_CFLAGS = $(WX_CFLAGS) $(CFLAGS)
libhipgui_la_LIBADD =

INCLUDES = -I$(HIPL_LINUX_INCLUDE) -I$(PWD) -I$(HIPL_LIBINET6_INCLUDE)
INCLUDES += -I$(HIPL_LIBINET6) -I$(HIPL_LINUX_MODULE) -I$(HIPL) -I$(HIPL_HIPD)
INCLUDES += $(WX_INCLUDES) -I$(HIPL_AGENT) -I$(HIPL_LIBHIPTOOL)
