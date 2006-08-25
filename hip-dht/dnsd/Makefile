CC = gcc
CFLAGS  = -g 
PROGRAM = dht-dnsd

TARGETS=config base64 dns hex sha validator

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
	@rm -f $(TARGETS) $(PROGRAM) $(LIBRARY)



