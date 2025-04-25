#ifndef OS_INFO
#define OS_INFO 1

#include "my_string.h"
#include "types.h"
#include "json_util.h"

#define SSTARTUP_UNKNOWN    (ushort_t)-1
#define SSTATUS_UNKNOWN     (ushort_t)-1

#define SSTATE_STOPPED      0
#define SSTATE_RUNNING      1
#define SSTATE_PAUSED       2

#define MAX_SERVICES    512
#define MIN_SERVICES    5
#define CHUNK_SERVICES  25


#define SRETRIEVE_OK            0
#define SRETRIEVE_SYSTEM_ERROR  1
#define SRETRIEVE_MEM_ERROR     2
#define SRETRIEVE_UNKNOWN (ushort_t)-1

typedef struct _winService
{
    wchar_t * name;         // service name (i.e DisplayName in Windows)
    wchar_t * desc;         // service description (Windows specific)
    int     startup;        // startup strategy (Windows specific)
    int     status;         // status of this service (Windows specific)
    boolean denied;         // can we access to this service or not?

} winservice_t;

typedef struct _wpack
{
    winservice_t * data;    // array of services
    int count;              // current count of services
    int capacity;           // allocated size so far

} services_t;

typedef struct _os
{
    long                ID;
    very_long_t         Uptime;
    len_t               BytesAvailable;
    len_t               BytesUsed;
    len_small_t         WinMajor;
    len_small_t         WinMinor;
    len_small_t         BuildNumber;
    len_small_t         NumberOfProcessors;
    wchar_t             *              ServicePack; // unused
    wchar_t             *              Win32Dir;   // windows directory
    wchar_t             *              TempDir;     // temporary directory
    unix_time_t         *              LocalTime;   // time of computer

    const char *        MachineType;
    const char *        Processor;

    services_t          services; // all services;
    
    json_define_callback_type_to(_os, char*);
    json_define_callback_type_from(_os, char*);
    
} OSInfo, *POSInfo;



json_declare_fn_to_json(OSInfo, char*);
json_declare_fn_from_json(OSInfo, char*);

POSInfo AllocateAndInitializeOSInfo();
POSInfo GetLatestOsInfo();
void OSInfoFree(POSInfo * ptr);
void GetWindowsVersion(POSInfo value);
int GetAllWindowsServices(services_t *pack);
#endif