AUTOMAKE_OPTIONS = foreign

CFLAGS = $(hipl_common_cflags)
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)

INCLUDES = $(hipl_common_include_paths)

LDADD = 

CFLAGS += $(HIPL_XMLL)

if HIP_OPENWRT
  LDADD += $(OPENWRT_LIB_STATIC)
else
  LDADD += 
endif

if HIP_FORCE_SHLIB
  LDADD += -linet6 -lhiptool -lhipcore
else
  LDADD += ../libhipcore/.libs/libhipcore.a
  LDADD += ../libhiptool/.libs/libhiptool.a
endif

LDFLAGS = @LDFLAGS@ -L$(HIPL_LIBHIPTOOL_LIB) -L$(HIPL_LIBHIPCORE_LIB)

if HIP_OPENWRT
LDFLAGS += $(OPENWRT)
endif

bin_PROGRAMS = hc_performance
bin_PROGRAMS += auth_performance

hc_performance_SOURCES = hc_performance.c
auth_performance_SOURCES = auth_performance.c