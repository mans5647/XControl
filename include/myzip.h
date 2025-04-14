#ifndef MYZIP
#define MYZIP

#include <stdint.h>
#include "zlib.h"


#define Z_MAX               Z_BEST_COMPRESSION
#define Z_MIN               Z_BEST_SPEED
#define Z_BALANCE           Z_DEFAULT_COMPRESSION

char * encode_deflate(char *data, uint32_t size, uint32_t *out_size, int level);
char * deflate_compress_balanced(const char ** data, uint64_t size, uint64_t * out_size);



#endif