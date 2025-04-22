#ifndef FILE_UTIL
#define FILE_UTIL

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef AMD64
    #define MAX_BUF SIZE_MAX
#else
    #define MAX_BUF UINT_MAX
#endif

#define FBUF_MAX MAX_BUF

#define FBUF_NO_ERR     (0)
#define FBUF_IO_ERR     (-1)
#define FBUF_NOTFOUND   (-2)
#define FBUF_ALLOC      (-3)

struct fbuf
{
    char * data;
    uint32_t bytes;
    uint32_t capacity;
};

typedef struct      fbuf    fbuf_t;
typedef fbuf_t *            fbuf_ptr;

void        fbuf_init(fbuf_ptr);
fbuf_ptr    fbuf_new_with_size(uint32_t bytes);
void        fbuf_free(fbuf_ptr ptr);
void fbuf_clear(fbuf_ptr ptr);
wchar_t *current_dir();
wchar_t *   exe_dir();
wchar_t *   concat_filename(wchar_t *path, const wchar_t * filename);
int         read_file(fbuf_ptr buffer, const wchar_t *filename);

#endif