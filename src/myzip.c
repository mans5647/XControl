#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "myzip.h"


#define MAX_BLOCK           USHRT_MAX
#define DEFAULT_CHUNK       128
#define INIT_BUFFER_SIZE    256

#define BUF_UNCHANGED       1
#define BUF_ALLOC_ERROR     2
#define BUF_ALLOC_OK        0


typedef struct Buffer
{
    Bytef * data;
    size_t capacity;
    size_t size;

} Buffer;

static void arrange_input_buffer(z_streamp dstream, uint32_t * available_size)
{
    dstream->avail_in = min(*available_size, UINT_MAX);
    *available_size -= dstream->avail_in;
}

static uint32_t GetBufferLen(const Buffer * b, const z_streamp stream)
{
    return ((uint32_t)(b->capacity) - stream->avail_out);
}

static int grow_buffer(Buffer *buf, uint32_t how_much, z_streamp stream)
{
    uint32_t old_cap = (uint32_t)(buf->capacity);
    uint32_t new_cap = old_cap + how_much;

    Bytef *new_data = realloc(buf->data, new_cap);
    if (!new_data) return BUF_ALLOC_ERROR;

    buf->data = new_data;
    buf->capacity = new_cap;

    stream->next_out = (buf->data + old_cap);
    stream->avail_out = how_much;

    return BUF_ALLOC_OK;
}


static int init_buffer(Buffer * buf)
{
    buf->data = malloc(INIT_BUFFER_SIZE);
    
    if (!buf->data) return BUF_ALLOC_ERROR;
    
    buf->capacity = INIT_BUFFER_SIZE;
    buf->size = 0;


    return BUF_ALLOC_OK;
}



char *encode_deflate(char *data, uint32_t size, uint32_t *out_size, int level)
{
    z_stream data_stream;
    int32_t err;

    data_stream.zalloc = Z_NULL;
    data_stream.zfree = Z_NULL;
    data_stream.opaque = Z_NULL;

    err = deflateInit(&data_stream, level);
    if (err != Z_OK) {
        return NULL;
    }

    Buffer buf = {0};
    if (init_buffer(&buf) != BUF_ALLOC_OK) {
        deflateEnd(&data_stream);
        return NULL;
    }

    data_stream.avail_out = buf.capacity;
    data_stream.next_out = buf.data;
    data_stream.next_in = (Bytef *)data;

    int flush;
    do
    {
        arrange_input_buffer(&data_stream, &size);
        flush = (size == 0) ? Z_FINISH : Z_NO_FLUSH;

        do
        {
            if (data_stream.avail_out == 0) {
                if (grow_buffer(&buf, DEFAULT_CHUNK, &data_stream) != BUF_ALLOC_OK) {
                    deflateEnd(&data_stream);
                    free(buf.data);
                    return NULL;
                }
            }

            err = deflate(&data_stream, flush);
            if (err == Z_STREAM_ERROR) {
                deflateEnd(&data_stream);
                free(buf.data);
                return NULL;
            }
        } while (data_stream.avail_out == 0);

        assert(data_stream.avail_in == 0);
    } while (flush != Z_FINISH);

    assert(err == Z_STREAM_END);

    *out_size = data_stream.total_out;
    deflateEnd(&data_stream);

    return buf.data;
}