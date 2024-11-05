SRCS = gc.c f00d_emu.c crypto/aes.c crypto/aes_cbc.c crypto/aes_cmac.c
OBJS = $(SRCS:%.c=build/%.o)

CFLAGS = -Wall -O2

all: libcmd56.a

build/crypto:
	mkdir -p $@

build/%.o: cmd56/%.c | build/crypto
	$(CC) $(CFLAGS) -c -nostdlib -fPIC $< -o $@

libcmd56.a: $(OBJS)
	ar rcs $@ $^

clean:
	rm -r build libcmd56.a


build/test.o: test/main.c
	$(CC) $(CFLAGS) -c $< -o $@

build/test: build/test.o libcmd56.a
	$(CC) $(CFLAGS) -L. $< -lcmd56 -o $@
