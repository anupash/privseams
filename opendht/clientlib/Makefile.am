##############

AUTOMAKE_OPTIONS = foreign

# HIP additions to the flags.
INCLUDES = $(hipl_common_include_paths) -Iinclude_glibc
CFLAGS = $(hipl_common_cflags)

lib_LTLIBRARIES = libdhtresolver.la
libdhtresolver_la_SOURCES  = resolver.c ../opendht_interface.c

bin_PROGRAMS = teststub
teststub_SOURCES = teststub.c
teststub_LDADD = .libs/libdhtresolver.a ../../libinet6/.libs/libinet6.a

../../libinet6/.libs/libinet6.a:
	$(MAKE) -C $(HIPL)/libinet6

##############

#CC = gcc
#CFLAGS  = -g 
#AR = ar
#PROGRAM = dhtresolver
#LIBRARY = resolver.a

#TARGETS=resolver teststub

#SHARE=../share
#DHTIF=opendht_interface 
#RPCCLIENT=rpcif_client 
#RPCXDR=rpcif_xdr
#INCLUDEDIRS = -I../share
#LIBDIRS = 
#LIBS = 
#OBJECTS = $(TARGETS:%=%.o)
#LDFLAGS = $(LIBDIRS) $(LIBS)

#all: $(PROGRAM)
#
#$(PROGRAM): $(OBJECTS) $(DHTIF:%=%.o) 
#	@echo "Linking..."
#	@$(CC) -o $@ $(OBJECTS) $(LDFLAGS) $(DHTIF:%=%.o) $(RPCCLIENT:%=%.o) $(RPCXDR:%=%.o)
#	@$(AR) r $(LIBRARY) $(OBJECTS)  $(DHTIF:%=%.o) $(RPCCLIENT:%=%.o) $(RPCXDR:%=%.o)
#
#$(OBJECTS):
#	@echo "Compiling files...$@"
#	@$(CC) $(CFLAGS) $(INCLUDEDIRS) -c $(TARGETS:%=%.c)
#
#$(DHTIF:%=%.o):
#	@echo "Compiling shared utils $@"
#	@$(CC) $(CFLAGS) $(INCLUDEDIRS) -c $(SHARE)/$(DHTIF:%=%.c)
#	@$(CC) $(CFLAGS) $(INCLUDEDIRS) -c $(SHARE)/$(RPCCLIENT:%=%.c)
#	@$(CC) $(CFLAGS) $(INCLUDEDIRS) -c $(SHARE)/$(RPCXDR:%=%.c)
#
#clean:
#	@echo "Cleaning..."
#	@rm -f *.o
#	@rm -f $(TARGETS) $(PROGRAM)



