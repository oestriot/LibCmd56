CC = gcc
RANLIB = ranlib
AR = ar
ARFLAGS = rc
OUTDIR = build
LIBDIR = $(realpath ./$(OUTDIR))
INCDIR = $(realpath ./cmd56)

CFLAGS = -static -O3 -DLOGGING_ENABLED=1
LDFLAGS = -lcmd56

OBJ = cmd56/crypto/aes.o cmd56/crypto/aes_cmac.o cmd56/crypto/aes_cmac.o \
      cmd56/cmd56.o cmd56/cmd56_sm.o cmd56/gc.o cmd56/vita.o

LIBS = libcmd56.a

all: mkdir libs test_pc

libs: $(LIBS)

.PHONY: mkdir
mkdir:
	-mkdir $(OUTDIR)
	
.PHONY: clean
clean:
	-find . -name "*.o" -delete
	-rm -rf $(OUTDIR)
	
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) -nostdlib
	
libcmd56.a: $(OBJ)  
	$(AR) $(ARFLAGS) $(OUTDIR)/$@ $^
	$(RANLIB) $(OUTDIR)/$@ 

test_pc: libs
	$(CC) -o $(OUTDIR)/$@ test_pc/main.c -I$(INCDIR) -L$(LIBDIR) $(LDFLAGS) $(CFLAGS) 