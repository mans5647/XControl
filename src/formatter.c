#include <Windows.h>
#include <limits.h>
#include "formatter.h"

#define FMT_WIN_MAX_SZ 10000

char * FormatWinError(uint32_t err)
{
    TCHAR * buf = NULL;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM
        , NULL, err, 0, (LPTSTR)&buf, FMT_WIN_MAX_SZ, NULL);

    return buf;
}

void FreeMessage(void * buf)
{
    LocalFree(buf);
}