#ifndef UTIL
#define UTIL
#include <stdio.h>
#include <time.h>
#include "string_fwd.h"

#define NewMemory(type, bytes) (type*)malloc(bytes)
#define AllocCount(type, count) NewMemory(type, sizeof(type) * count)
#define DataRealloc(type, bytes, block) (type*)realloc(block,bytes)
#define DataReallocCount(type, count, block) DataRealloc(type, sizeof(type) * count, block)
#define FreeMemoryBlock(block) free(block)
#define CRLF "\r\n"

#endif