SRCS = gc.c f00d_emu.c crypto/aes.c crypto/aes_cbc.c crypto/aes_cmac.c
OBJS = $(SRCS:%.c=build/%.o)

CFLAGS = -Wall -O2 -nostdlib

all: cmd56.so

build/crypto:
	mkdir -p $@

build/%.o: cmd56/%.c | build/crypto
	$(CC) $(CFLAGS) -c -fPIC $< -o $@

cmd56.so: $(OBJS)
	$(CC) $(CFLAGS) -shared $(OBJS) -o $@

clean:
	rm -r build cmd56.so
