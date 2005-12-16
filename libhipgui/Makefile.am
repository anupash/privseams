## Makefile.am for HIP GUI
CFLAGS = $(hipl_common_cflags) -O0

WX_INCLUDES := $(shell wx-config --cxxflags)
WX_CFLAGS := $(shell wx-config --libs)

lib_LTLIBRARIES = libhipgui.la

libhipgui_la_SOURCES = hipagent.cpp hipcontext.cpp hipinterface.cpp hipkey.cpp hippersonality.cpp hiptab.cpp agent_interface.cpp

libhipgui_la_CFLAGS = $(WX_CFLAGS) $(CFLAGS)
#libhipgui_la_LIBADD =

INCLUDES = $(hipl_common_include_paths)
INCLUDES += $(WX_INCLUDES) -I$(HIPL_AGENT)
