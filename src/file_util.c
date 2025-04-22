#include "file_util.h"
#include "win_misc.h"
#include "util.h"
#include <Windows.h>

#define ActionIfNonNull(statement, action) (void)((statement) ? action : (-1))

void fbuf_init(fbuf_ptr value)
{
    value->bytes = 0;
    value->capacity = 0;
    value->data = NULL;
}

fbuf_ptr fbuf_new_with_size(uint32_t bytes)
{
    fbuf_ptr value = AllocCount(fbuf_t, 1);

    if (!value) return NULL;

    value->data = AllocCount(char, bytes);
    if (!value->data) {
        free(value);
        return NULL;
    }

    value->bytes = bytes;
    return value;
}

void fbuf_free(fbuf_ptr ptr)
{
    if (!ptr) return;

    free(ptr->data);
    free(ptr);
}

void fbuf_clear(fbuf_ptr ptr)
{
    if (!ptr) return;
    free(ptr->data);
    
    ptr->data = NULL;
    ptr->bytes = 0;
}

wchar_t *current_dir()
{
    wchar_t* path;
    DWORD res;
    res = GetCurrentDirectoryW(0, NULL);
    
    if (!res) return NULL;

    path = malloc(sizeof(wchar_t) * res + 1);
    GetCurrentDirectoryW(res, path);
    path[res] = L'\0';
    return path;
}

wchar_t *exe_dir()
{
    static wchar_t exePath[MAX_PATH + 1];
    DWORD dwChars;
    dwChars = GetModuleFileNameW(NULL, exePath, MAX_PATH);
    
    while (exePath[--dwChars] != L'\\')
    {
        exePath[dwChars] = '\0';
    }

    return exePath;
}

wchar_t * concat_filename(wchar_t * path, const wchar_t * filename)
{
    return wcscat(path, filename);
}

int read_file(fbuf_ptr buffer, const wchar_t* filename)
{
    int32_t err = FBUF_IO_ERR;
    size_t file_size = 0;
    
    if (!IsFileExistsWin32(filename)) {
        return FBUF_NOTFOUND;
    }

    void * fileHandle = OpenFileWin32(filename);

    if (!fileHandle) {
        return FBUF_IO_ERR;
    }

    char * data = ReadFileAllWin32(fileHandle, &file_size);

    if (!data) {
        return FBUF_IO_ERR;
    }

    buffer->data = data;
    buffer->bytes = file_size;

    return FBUF_NO_ERR;
}
