SRCS = gc.c f00d_emu.c crypto/aes.c crypto/aes_cmac.c
OBJS = $(SRCS:%.c=build/%.o)
ASMS = $(SRCS:%.c=build/%.s)

CFLAGS = -Wall -Wpedantic -Os -std=c17

all: libcmd56.a

build:
	mkdir -p build

build/crypto:
	mkdir -p $@

build/%.o: cmd56/%.c | build/crypto
	$(CC) $(CFLAGS) -c -nostdlib $< -o $@

build/%.s: cmd56/%.c | build/crypto
	$(CC) $(CFLAGS) -S $< -o $@

libcmd56.a: $(OBJS)
	ar rcs $@ $^

asm: $(ASMS)

clean:
	rm -r build libcmd56.a


build/test.o: test/main.c build
	$(CC) $(CFLAGS) -c $< -o $@

build/test: build/test.o libcmd56.a
	$(CC) $(CFLAGS) -L. $< -lcmd56 -o $@
