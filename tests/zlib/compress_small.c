#include "myzip.h"
#include "file_util.h"
#include <string.h>


#define FILENAME L"test_small_data"
#define COMPRESSED_FILENAME L"out_zip_small"

void compressed_writefile(char * data, uint32_t size)
{

    wchar_t * path_to_exe, *full_path;

    path_to_exe = exe_dir();

    full_path = concat_filename(path_to_exe, COMPRESSED_FILENAME);

    FILE *fp = _wfopen(full_path, L"wb");

    fwrite(data, 1, size, fp);
    fclose(fp);
}


int test_is_compressed_rightly_uncompressed()
{
    fbuf_t inbuf;
    int32_t err;
    uint32_t out_size;
    wchar_t * path_to_exe, *full_path;
    
    fbuf_init(&inbuf);

    path_to_exe = exe_dir();

    full_path = concat_filename(path_to_exe, FILENAME);
    err = read_file(&inbuf, full_path);

    if (err != FBUF_NO_ERR) return 1;

    // test our auto-reziable buffer algorithm
    char * encoded = encode_deflate(inbuf.data, inbuf.bytes, &out_size, Z_BALANCE);
    
    fbuf_ptr outbuf = fbuf_new_with_size(inbuf.bytes);

    if (!outbuf) return 1;

    int zerror = uncompress((Bytef*)outbuf->data, (uLongf*)&outbuf->bytes, (const Bytef*)encoded, (uLong)out_size);

    if (zerror != Z_OK) return 1;

    return (memcmp(inbuf.data, outbuf->data, inbuf.bytes));
}


int main(int argc, char ** argv)
{
    int err;
    err = (!test_is_compressed_rightly_uncompressed()) ? 0 : 1;
    return err;
}