#ifndef RNG_H
#define RNG_H 1
#include "compiler_defs.h"

void rand_bytes(void* buf, size_t size);

#define rand_bytes_or_w_80(buf, size) do { rand_bytes(buf, size); \
										   ((uint8_t*)buf)[0] |= 0x80; } while(0);\

#endif /* RNG_H */