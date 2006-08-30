CC = gcc
CFLAGS  = -g 
AR = ar
PROGRAM = dhtresolver
LIBRARY = resolver.a

TARGETS=resolver teststub

SHARE=../share
DHTIF=opendht_interface 
RPCCLIENT=rpcif_client 
RPCXDR=rpcif_xdr
INCLUDEDIRS = -I../share
LIBDIRS = 
LIBS = 
OBJECTS = $(TARGETS:%=%.o)
LDFLAGS = $(LIBDIRS) $(LIBS)

all: $(PROGRAM)

$(PROGRAM): $(OBJECTS) $(DHTIF:%=%.o) 
	@echo "Linking..."
	@$(CC) -o $@ $(OBJECTS) $(LDFLAGS) $(DHTIF:%=%.o) $(RPCCLIENT:%=%.o) $(RPCXDR:%=%.o)
	@$(AR) r $(LIBRARY) $(OBJECTS)  $(DHTIF:%=%.o) $(RPCCLIENT:%=%.o) $(RPCXDR:%=%.o)

$(OBJECTS):
	@echo "Compiling files...$@"
	@$(CC) $(CFLAGS) $(INCLUDEDIRS) -c $(TARGETS:%=%.c)

$(DHTIF:%=%.o):
	@echo "Compiling shared utils $@"
	@$(CC) $(CFLAGS) $(INCLUDEDIRS) -c $(SHARE)/$(DHTIF:%=%.c)
	@$(CC) $(CFLAGS) $(INCLUDEDIRS) -c $(SHARE)/$(RPCCLIENT:%=%.c)
	@$(CC) $(CFLAGS) $(INCLUDEDIRS) -c $(SHARE)/$(RPCXDR:%=%.c)

clean:
	@echo "Cleaning..."
	@rm -f *.o
	@rm -f $(TARGETS) $(PROGRAM)



