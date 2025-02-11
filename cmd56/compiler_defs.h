#ifndef COMPILER_DEFS_H
#define COMPILER_DEFS_H 1

#ifdef __GNUC__
#define PACK( __Declaration__ ) __Declaration__ __attribute__((__packed__))
#endif

#ifdef _MSC_VER
#define PACK( __Declaration__ ) __pragma(pack(push, 1) ) __Declaration__ __pragma(pack(pop))

#define __builtin_bswap16 _byteswap_ushort
#endif

#ifndef NULL // to avoid relying on std includes
#define NULL ((void*)0)
#endif 

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned long long uint64_t;
typedef long long int64_t;

typedef enum bool {
    true = 1,
    false = 0
} bool;

#ifndef _MSC_VER
typedef __SIZE_TYPE__ size_t;
#else
#ifdef _WIN64
typedef uint64_t size_t;
#else
typedef uint32_t size_t;
#endif
#endif

#if !defined(_MSC_VER) && !defined(__GNUC__)
static inline memcpy(void* dst, void* src, size_t len) {
    for (int i = 0; i < len; i++) {
        ((uint8_t*)dst)[i] = ((uint8_t*)src[i]);
    }
}
static inline memset(void* dst, char v, size_t len) {
    for (int i = 0; i < len; i++) {
        ((uint8_t*)dst)[i] = ((uint8_t)v);
    }
}
static inline memcmp(void* a, void* b, size_t len) {
    size_t count = len;
    uint8_t* s1 = a;
    uint8_t* s2 = b;
    while (count-- > 0)
    {
        if (*s1++ != *s2++) {
            return s1[-1] < s2[-1] ? -1 : 1;
        }
    }
    return 0;
}
#else
void* memset(void* dst, int v, size_t len);
void* memcpy(void* dst, const void* src, size_t len);
int memcmp(void* a, void* b, size_t len);
#endif

#endif