#define WIN32_LEAN_AND_MEAN

#include "OSInfo.h"
#include "my_string.h"
#include "util.h"
#include "win_misc.h"
#include <malloc.h>
#include <cJSON.h>
#include <Windows.h>

#define MAX_COMP_NAME MAX_COMPUTERNAME_LENGTH + 1

#define NumberConv(t, expr) ((t)expr)

char * OSInfoToJson(const OSInfo * value)
{
    cJSON * osInfoJson = cJSON_CreateObject();
    cJSON_AddNumberToObject(osInfoJson, "id", NumberConv(double, value->ID));
    cJSON_AddNumberToObject(osInfoJson, "uptime", NumberConv(double, value->Uptime));
    cJSON_AddNumberToObject(osInfoJson, "mem_av", NumberConv(double, value->BytesAvailable));
    cJSON_AddNumberToObject(osInfoJson, "mem_usd", NumberConv(double, value->BytesUsed));
    char * data = cJSON_PrintUnformatted(osInfoJson);
    cJSON_Delete(osInfoJson);
    return data;
}


POSInfo AllocateAndInitializeOSInfo()
{
    POSInfo value = NewMemory(OSInfo, sizeof(OSInfo));
    value->BytesAvailable = 0;
    value->BytesUsed = 0;
    value->Uptime = 0;
    value->ID = -1;
    return value;
}

POSInfo GetLatestOsInfo()
{
    POSInfo myOsInfo = AllocateAndInitializeOSInfo();
    MEMORYSTATUSEX memStat = {0};

    memStat.dwLength = sizeof(memStat);

    GlobalMemoryStatusEx(&memStat);

    myOsInfo->ID = -1;
    myOsInfo->BytesAvailable    = memStat.ullAvailPhys;
    myOsInfo->BytesUsed         =   (memStat.ullTotalPhys - memStat.ullAvailPhys);
    myOsInfo->Uptime            = GetRunningTime();
    return myOsInfo;
}

void OSInfoFree(POSInfo * ptr)
{
    POSInfo real = (*ptr);
    free(real);
}