/*
*	LibCmd56 from the Estroit team!
*	the only functional implementation of vita gamecart authentication!
*/

#ifndef COMPILER_DEFS_H
#define COMPILER_DEFS_H 1

#define HAVE_LIBC (defined(__GLIBC__) || defined(_MSC_VER))

#ifdef __GNUC__
#define PACK( declaration ) declaration __attribute__((__packed__))
#elif _MSC_VER
#define PACK( declaration ) __pragma(pack(push, 1) ) declaration __pragma(pack(pop))
#endif

#ifdef _MSC_VER
#define endian_swap _byteswap_ushort
#elif __GNUC__
#define endian_swap __builtin_bswap16
#endif

#ifndef NULL 
#define NULL ((void*)0)
#endif

#if !HAVE_LIBC // if we dont have libc, specify our own versions of stdint variables.
	typedef signed char int8_t;
	typedef unsigned char uint8_t;
	typedef signed short int int16_t;
	typedef unsigned short int uint16_t;
	typedef signed int int32_t;
	typedef unsigned int uint32_t;
	typedef signed long long int int64_t;
	typedef unsigned long long int uint64_t;
#else
	#include <stdint.h>
#endif

typedef enum boolean {
    TRUE = 1,
    FALSE = 0
} boolean;

#if defined(__GNUC__)
typedef __SIZE_TYPE__ size_t;
typedef size_t uintptr_t;
#elif defined(_MSC_VER)

#ifdef _WIN64
typedef unsigned __int64 size_t;
typedef unsigned __int64 uintptr_t;
#else
typedef unsigned int     size_t;
typedef unsigned int     uintptr_t;
#endif

#endif

#ifdef _MSC_VER
#define inline __forceinline
#endif

#if !HAVE_LIBC // if you dont have libc, we have to provide our own ..
static inline void* __impl_memcpy(void* buf, void const* src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        ((uint8_t*)buf)[i] = ((uint8_t*)src)[i];
    }
    return buf;
}
static inline void* __impl_memset(void* buf, int c, size_t n) {
    for (size_t i = 0; i < n; i++) {
        ((uint8_t*)buf)[i] = ((uint8_t)c);
    }
    return buf;
}
static inline int __impl_memcmp(void const* a, void const* b, size_t len) {
    size_t count = len;
    uint8_t* s1 = (uint8_t*)a;
    uint8_t* s2 = (uint8_t*)b;
    while (count-- > 0)
    {
        if (*s1++ != *s2++) {
            return s1[-1] < s2[-1] ? -1 : 1;
        }
    }
    return 0;
}

#define memset __impl_memset
#define memcpy __impl_memcpy
#define memcmp __impl_memcmp
#else // we have libc, so just use the default ones.
#include <string.h>
#endif

#ifndef offsetof
#define offsetof(st, m) ((size_t)&(((st*)0)->m))
#endif

#endif