#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#ifndef UNICODE
#define UNICODE
#endif


#include "OSInfo.h"
#include "my_string.h"
#include "util.h"
#include "win_misc.h"
#include <malloc.h>
#include <cJSON.h>
#include <Windows.h>

#define MAX_COMP_NAME MAX_COMPUTERNAME_LENGTH + 1

#define NumberConv(t, expr) ((t)expr)

#define INTERNAL_SRETRIEVE_MEM_ERROR -1
#define INTERNAL_SRETRIEVE_OK 0
#define INTERNAL_SRETRIEVE_SERVICE_SKIP 3

void _winServiceInit(winservice_t * p)
{
    p->denied = false;
    p->desc = NULL;
    p->name = NULL;
    p->startup = SSTARTUP_UNKNOWN;
    p->status = SSTATUS_UNKNOWN;
}

void _winServiceCopy(winservice_t * dest, const winservice_t * src)
{
    size_t nameLen, descLen;

    dest->denied = src->denied;
    dest->startup = src->startup;
    dest->status = src->status;

    nameLen = wcslen(src->name) + 1;
    descLen = wcslen(src->desc) + 1;

    dest->name = malloc(nameLen * sizeof(wchar_t));
    dest->desc = malloc(descLen * sizeof(wchar_t));

    wcscpy(dest->name, src->name);
    wcscpy(dest->desc, src->desc);

    dest->name[nameLen - 1] = L'\0';
    dest->desc[descLen - 1] = L'\0';
}

// utility. initalize services
void servicesInit(services_t * ptr)
{
    ptr->count = 0;
    ptr->capacity = MIN_SERVICES;
    ptr->data = malloc(sizeof(winservice_t) * ptr->capacity);
}

// utility. adds service to end of the array
void servicesAdd(services_t * pack, winservice_t * value)
{
    if (pack->count >= pack->capacity) {
        /* resize array */
        pack->data = realloc(pack->data, (pack->capacity + CHUNK_SERVICES) * sizeof(winservice_t));
        pack->capacity += CHUNK_SERVICES;
    }

    _winServiceInit(&pack->data[pack->count]);
    
    _winServiceCopy(&pack->data[pack->count], value);

    pack->count += 1;
}

// utility. constructs service from native Windows service and adds it at the end of the array
int servicesAddNewFromNative(services_t * pack, LPENUM_SERVICE_STATUS_PROCESS esp, SC_HANDLE scManager)
{
    DWORD dwErr, cbBufSize;
    SC_HANDLE hService;
    LPSERVICE_DESCRIPTION lpsd = NULL;
    LPQUERY_SERVICE_CONFIG lpsc = NULL;
    
    DWORD cbBytesNeededDesc, dwBytesNeeded;
    if (pack->count >= pack->capacity) {
        /* resize array */
        void * nVec = realloc(pack->data, (pack->capacity + CHUNK_SERVICES) * sizeof(winservice_t));
        if (!nVec) {
            /* not enough memory for more elements */
            return INTERNAL_SRETRIEVE_MEM_ERROR;
        }

        pack->data = nVec;
        pack->capacity += CHUNK_SERVICES;
    }

    winservice_t * lastElement = &pack->data[pack->count];
    _winServiceInit(lastElement);
    lastElement->name = (esp->lpDisplayName) ? _wcsdup(esp->lpDisplayName) : NULL;
    lastElement->status = esp->ServiceStatusProcess.dwCurrentState;

    // opening service;

    hService = OpenService(scManager, esp->lpServiceName, SERVICE_QUERY_CONFIG);

    if (!hService) {
        // skip service and set it to invalid
        lastElement->denied = true;
        pack->count++;
        return INTERNAL_SRETRIEVE_SERVICE_SKIP;
    }

    // now, assign variables
    // first, getting description 
    
    dwErr = QueryServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, NULL, 0, &cbBytesNeededDesc);

    if (!dwErr) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            cbBufSize = cbBytesNeededDesc;
            lpsd = LocalAlloc(LMEM_FIXED, cbBytesNeededDesc);
        } else {
            cbBufSize = 0;
        }
    }
    
    if (QueryServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION,(LPBYTE) lpsd, cbBufSize, &cbBytesNeededDesc)) {
        lastElement->desc = _wcsdup(lpsd->lpDescription);
    }
    
    
    // getting service config

    if (!QueryServiceConfig(hService, NULL, 0, &dwBytesNeeded)) {
        dwErr = GetLastError();
        if (ERROR_INSUFFICIENT_BUFFER == dwErr) {
            cbBufSize = dwBytesNeeded;
            lpsc = LocalAlloc(LMEM_FIXED, cbBufSize);
        } else {
            cbBufSize = 0;
        }
    }

    if (QueryServiceConfig(hService, lpsc, cbBufSize, &dwBytesNeeded)) {
        lastElement->startup = lpsc->dwStartType;
    }

    // free resources
    LocalFree(lpsd);
    LocalFree(lpsc);

    pack->count += 1;

    // close handle of service
    CloseServiceHandle(hService);
    return INTERNAL_SRETRIEVE_OK;
}

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
    value->BuildNumber = 0;
    value->MachineType = NULL;
    value->ServicePack = NULL;
    value->WinMajor = 0;
    value->WinMajor = 0;
    value->services.count = 0;
    value->services.data = NULL;
    
    return value;
}

POSInfo GetLatestOsInfo()
{
    POSInfo myOsInfo = AllocateAndInitializeOSInfo();
    MEMORYSTATUSEX memStat = {0};
    SYSTEM_INFO si;

    memStat.dwLength = sizeof(memStat);

    GlobalMemoryStatusEx(&memStat);
    GetSystemInfo(&si);

    // common information
    myOsInfo->ID = -1;
    myOsInfo->BytesAvailable    = memStat.ullAvailPhys;
    myOsInfo->BytesUsed         =   (memStat.ullTotalPhys - memStat.ullAvailPhys);
    myOsInfo->Uptime            = GetRunningTime();

    // type of processor
    switch (si.wProcessorArchitecture)
    {
        case PROCESSOR_ARCHITECTURE_ARM:
        case PROCESSOR_ARCHITECTURE_ARM64:
        {
            myOsInfo->Processor = "ARM";
            break;
        }
        case PROCESSOR_ARCHITECTURE_AMD64:
        {
            myOsInfo->Processor = "x64 (AMD или Intel)";
            break;
        }
        case PROCESSOR_ARCHITECTURE_INTEL:
        {
            myOsInfo->Processor = "x32 (Intel)";
            break;
        }
        default:
        {
            myOsInfo->Processor = "Неизвестно";
        }
    }

    // setting number of processors
    myOsInfo->NumberOfProcessors = si.dwNumberOfProcessors;
    
    // getting windows version for this instance
    GetWindowsVersion(myOsInfo);

    // getting all windows services for this instance
    GetAllWindowsServices(&myOsInfo->services);

    return myOsInfo;
}

void OSInfoFree(POSInfo * ptr)
{
    POSInfo real = (*ptr);
    free(real);
}

void GetWindowsVersion(POSInfo value)
{
    OSVERSIONINFOEXW osVersion;
    osVersion.dwOSVersionInfoSize = sizeof(osVersion);
    
    if (!GetVersionExW(&osVersion)) {
        return;
    }
    
    value->WinMajor = osVersion.dwMajorVersion;
    value->WinMinor = osVersion.dwMinorVersion;

    // machine type (server or workstation)
    switch (osVersion.wProductType) {
        case VER_NT_SERVER:
            value->MachineType = "Windows Сервер";
            break;
        case VER_NT_WORKSTATION:
            value->MachineType = "Клиент";
            break;
    }

    value->BuildNumber = osVersion.dwBuildNumber;
    

}



int GetAllWindowsServices(services_t * pack)
{
    SC_HANDLE scm;          // handle to scmanager
    DWORD cbBytesNeeded;    // size of the buffer
    DWORD err;              // last error of winapi
    LONG  errFunc;          // last error of this function
    DWORD dwServiceCount;
    LPENUM_SERVICE_STATUS_PROCESS services;        // buffer where data of services to be stored

    servicesInit(pack);

    scm = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);

    if (!scm) {
        return SRETRIEVE_SYSTEM_ERROR;
    }

    // getting the buffer size of the services
    err = EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, 
        SERVICE_WIN32, 
        SERVICE_STATE_ALL, 
        NULL,
        0,
        &cbBytesNeeded,
        &dwServiceCount,
        NULL, 
        NULL);

    // check is there more data

    if (!err) {
        if (ERROR_MORE_DATA == GetLastError()) {
            services = LocalAlloc(0, cbBytesNeeded);
            // getting services
            err = EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, 
                SERVICE_WIN32, 
                SERVICE_STATE_ALL, (LPBYTE)services,
                cbBytesNeeded,
                &cbBytesNeeded,
                &dwServiceCount,
                NULL, 
                NULL);
        } else {
            CloseServiceHandle(scm);
            return SRETRIEVE_SYSTEM_ERROR;
        }
    }

    // now, get information

    for (DWORD i = 0; i < dwServiceCount; i++) {
        (void)servicesAddNewFromNative(pack, &services[i], scm);
    }

    CloseServiceHandle(scm);
    return SRETRIEVE_OK;
}