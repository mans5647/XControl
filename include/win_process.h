#ifndef WIN_PROCESS
#define WIN_PROCESS

#include "my_string.h"
#include "types.h"
#include "json_util.h"


typedef struct WinProcess
{
    integer_t   Id;
    pstring_t   Name;
    len_t       WorkingSetSize;
    very_long_t CreationTime;
    very_long_t UserTime;
    pstring_t   UserName;
    pstring_t   Path;
    boolean     accessOk;
} WinProcess;


WinProcess * RetrieveAllProcesses(len_t * count, len_t * allocated);
WinProcess * GetAllProcesses(size_t * count);
void DestroyAllProcesses(WinProcess * ptr, len_t count);
char* WinProcessToJson(const WinProcess *, len_t);

#endif