/*
*	LibCmd56 from the Estroit team!
*	the only functional implementation of vita gamecart authentication!
*/

#if defined(_DEBUG) && defined(_MSC_VER)
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define LOG(...) printf(__VA_ARGS__)
#define LOG_BUFFER(buffer, size) for(int i = 0; i < size; i++) { LOG("%02X ", ((unsigned char*)buffer)[i]); }; LOG("\n");
#elif defined(_DEBUG) && defined(__vita__)
#include <vitasdkkern.h>
#define LOG(...) ksceKernelPrintf(__VA_ARGS__)
#define LOG_BUFFER(buffer, size) for(int i = 0; i < size; i++) { LOG("%02X ", ((unsigned char*)buffer)[i]); }; LOG("\n");
#else
#define LOG(...) /**/
#define LOG_BUFFER(buffer, size) /**/
#endif