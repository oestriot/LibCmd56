#ifndef COMPILER_DEFS_H
#define COMPILER_DEFS_H 1

#ifdef __GNUC__
#define PACK( __Declaration__ ) __Declaration__ __attribute__((__packed__))
#endif

#ifdef _MSC_VER
#define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop))

#define __builtin_bswap16 _byteswap_ushort
#endif

#endif