#include "file_util.h"


int main(int argc, char ** argv)
{
    fbuf_t buf;
    int32_t err;
    wchar_t * path_to_exe, *full_path;
    const wchar_t * filename = L"test_file";
    
    fbuf_init(&buf);

    path_to_exe = current_dir();

    full_path = concat_filename(path_to_exe, filename);
    err = read_file(&buf, full_path);

    if (err != FBUF_NO_ERR) return 1;

    return 0;
}