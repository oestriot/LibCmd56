/*
*	LibCmd56 from the Estroit team!
*	the only functional implementation of vita gamecart authentication!
*/

#if defined(_DEBUG) && defined(_MSC_VER)
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define PRINT_STR(...) printf(__VA_ARGS__)
#define PRINT_BUFFER(buffer) PRINT_BUFFER_LEN(buffer, sizeof(buffer))
#define PRINT_BUFFER_LEN(buffer, size) for(int i = 0; i < size; i++) { PRINT_STR("%02X ", ((unsigned char*)buffer)[i]); }; PRINT_STR("\n");
#elif defined(_DEBUG) && defined(__vita__)
#include <vitasdkkern.h>
#define PRINT_STR(...) ksceKernelPrintf(__VA_ARGS__)
#define PRINT_BUFFER(buffer) PRINT_BUFFER_LEN(buffer, sizeof(buffer))
#define PRINT_BUFFER_LEN(buffer, size) for(int i = 0; i < size; i++) { PRINT_STR("%02X ", ((unsigned char*)buffer)[i]); }; PRINT_STR("\n");
#else
#define PRINT_STR(...) /**/
#define PRINT_BUFFER(buffer) /**/
#define PRINT_BUFFER_LEN(buffer, size) /**/
#endif