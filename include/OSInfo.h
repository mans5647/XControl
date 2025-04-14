#ifndef OS_INFO
#define OS_INFO 1

#include "my_string.h"
#include "types.h"
#include "json_util.h"


typedef struct _os
{
    long        ID;
    very_long_t Uptime;
    len_t       BytesAvailable;
    len_t       BytesUsed;
    
    json_define_callback_type_to(_os, char*);
    json_define_callback_type_from(_os, char*);
    
} OSInfo, *POSInfo;



json_declare_fn_to_json(OSInfo, char*);
json_declare_fn_from_json(OSInfo, char*);

POSInfo AllocateAndInitializeOSInfo();
POSInfo GetLatestOsInfo();
void OSInfoFree(POSInfo * ptr);
#endif