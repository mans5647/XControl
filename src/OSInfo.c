#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#ifndef UNICODE
#define UNICODE
#endif


#include "OSInfo.h"
#include "my_string.h"
#include "util.h"
#include "win_misc.h"
#include "file_util.h"
#include "resource_monitor.h"
#include "resources_def.h"
#include <malloc.h>
#include <cJSON.h>
#include <Windows.h>
#include <VersionHelpers.h>

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
    DWORD dwErr, cbBufSize = 0;
    SC_HANDLE hService;
    LPSERVICE_DESCRIPTION lpsd = NULL;
    LPQUERY_SERVICE_CONFIG lpsc = NULL;
    DWORD cbBytesNeededDesc, dwBytesNeeded;
    
    // opening service;
    hService = OpenService(scManager, esp->lpServiceName, SERVICE_QUERY_CONFIG);

    if (!hService) {
        pack->data[pack->count].denied = true;
        return INTERNAL_SRETRIEVE_SERVICE_SKIP;
    }
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
    
    QueryServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION,(LPBYTE) lpsd, cbBufSize, &cbBytesNeededDesc);
    

    if (!QueryServiceConfig(hService, NULL, 0, &dwBytesNeeded)) {
        dwErr = GetLastError();
        if (ERROR_INSUFFICIENT_BUFFER == dwErr) {
            cbBufSize = dwBytesNeeded;
            lpsc = LocalAlloc(LMEM_FIXED, cbBufSize);
        } else {
            cbBufSize = 0;
        }
    }

    QueryServiceConfig(hService, lpsc, cbBufSize, &dwBytesNeeded);

    uint32_t index = pack->count;
    
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

    winservice_t * lastElement = &pack->data[index];
    _winServiceInit(lastElement);
    lastElement->denied = false;
    lastElement->name = (esp->lpDisplayName) ? _wcsdup(esp->lpDisplayName) : NULL;
    lastElement->desc = lpsd ? _wcsdup(lpsd->lpDescription) : NULL;
    lastElement->status = esp->ServiceStatusProcess.dwCurrentState;
    lastElement->startup = lpsc ? lpsc->dwStartType : SSTARTUP_UNKNOWN;

    // free resources
    LocalFree(lpsd);
    LocalFree(lpsc);
    CloseServiceHandle(hService);
    
    pack->count++;
    
    return INTERNAL_SRETRIEVE_OK;
}

char * OSInfoToJson(const OSInfo * value)
{
    cJSON * osInfoJson, * servicesArray, * adaptersArray;
    pstring_t windir, tempdir;
    char * result; // json string
    char * rwindir;
    char * rtempdir;
    byte * resourcesJson;
    osInfoJson = cJSON_CreateObject();
    
    cJSON_AddNumberToObject(osInfoJson, "id", NumberConv(double, value->ID));
    cJSON_AddNumberToObject(osInfoJson, "uptime", NumberConv(double, value->Uptime));
    cJSON_AddNumberToObject(osInfoJson, "mem_av", NumberConv(double, value->BytesAvailable));
    cJSON_AddNumberToObject(osInfoJson, "mem_usd", NumberConv(double, value->BytesUsed));
    cJSON_AddNumberToObject(osInfoJson, "windows_major", NumberConv(double, value->WinMajor));
    cJSON_AddNumberToObject(osInfoJson, "windows_minor", NumberConv(double, value->WinMinor));
    cJSON_AddNumberToObject(osInfoJson, "local_time", NumberConv(double, value->LocalTime));
    cJSON_AddNumberToObject(osInfoJson, "processors", NumberConv(double, value->NumberOfProcessors));
    cJSON_AddStringToObject(osInfoJson, "machine_type", value->MachineType);
    cJSON_AddStringToObject(osInfoJson, "processor", value->Processor);
    
    windir = CreateStringFromWideChars(value->Win32Dir, wcslen(value->Win32Dir));
    tempdir = CreateStringFromWideChars(value->TempDir, wcslen(value->TempDir));
    rwindir = GetNullTerminatedBytes(windir);
    rtempdir = GetNullTerminatedBytes(tempdir);

    cJSON_AddStringToObject(osInfoJson, "windir", rwindir);
    cJSON_AddStringToObject(osInfoJson, "tempdir", rtempdir);

    servicesArray = cJSON_CreateArray();

    for (int32_t i = 0; i < value->services.count; i++) {

        winservice_t * service;
        service = &value->services.data[i];
        if (!service->denied) {

            cJSON * serviceObj;
            pstring_t name, desc;
            char * rname;
            char * rdesc;

            rname = NULL;
            rdesc = NULL;

            name = NULL;
            desc = NULL;

            serviceObj = cJSON_CreateObject();
            cJSON_AddNumberToObject(serviceObj, "startup", NumberConv(double, service->startup));
            cJSON_AddNumberToObject(serviceObj, "status", NumberConv(double, service->status));

            if (service->name) {
                name = CreateStringFromWideChars(service->name, wcslen(service->name));
                rname = GetNullTerminatedBytes(name);
            }

            if (service->desc) {
                desc = CreateStringFromWideChars(service->desc, wcslen(service->desc));
                rdesc = GetNullTerminatedBytes(desc);
            }

            cJSON_AddStringToObject(serviceObj, "name", rname);
            cJSON_AddStringToObject(serviceObj, "desc", rdesc);
            cJSON_AddItemToArray(servicesArray, serviceObj);

            StringDestroy(name);
            StringDestroy(desc);
            free(rname);
            free(rdesc);
        }
    }
    // adding services to array
    cJSON_AddItemToObject(osInfoJson, "services", servicesArray);

    // creating json array of adapters and adding int to object
    if (value->adapters.size > 0) {

        adaptersArray = cJSON_CreateArray();
        for (int i = 0; i < value->adapters.size; i++) {
            
            // push utf-8 name for adapter
            pstring_t utfName = NULL;
            char * utfNameRaw = NULL;
            adapterinfo_t * adNext = &value->adapters.data[i];
            cJSON * adObj = cJSON_CreateObject();

            cJSON_AddNumberToObject(adObj, "speed", NumberConv(double, adNext->speed));
            cJSON_AddNumberToObject(adObj, "sent", NumberConv(double, adNext->sent));
            cJSON_AddNumberToObject(adObj, "received", NumberConv(double, adNext->received));
            cJSON_AddNumberToObject(adObj, "type", NumberConv(double, adNext->type));
            
            utfName = CreateStringFromWideChars(adNext->name, wcslen(adNext->name));
            utfNameRaw = GetNullTerminatedBytes(utfName);
            
            cJSON_AddStringToObject(adObj, "name", utfNameRaw);
            cJSON_AddStringToObject(adObj, "desc", adNext->desc);

            cJSON_AddItemToArray(adaptersArray, adObj);
            // clear utf-8 name for adapter
            StringDestroy(utfName);
            free(utfNameRaw);
        }
        cJSON_AddItemToObject(osInfoJson, "adapters", adaptersArray);
    }

    // adding raw json of resources to array
    resourcesJson = resource_stats_to_json(value->resources);

    if (resourcesJson) {
        cJSON_AddRawToObject(osInfoJson, "resources", resourcesJson);
        free(resourcesJson);
    }

    result = cJSON_Print(osInfoJson);
    cJSON_Delete(osInfoJson);
    StringDestroy(windir);
    StringDestroy(tempdir);
    free(rwindir);
    free(rtempdir);
    return result;
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
    value->resources = NULL;
    return value;
}

POSInfo GetLatestOsInfo()
{
    POSInfo myOsInfo = AllocateAndInitializeOSInfo();
    MEMORYSTATUSEX memStat = {0};
    SYSTEM_INFO si;
    FILETIME ftSysTime, ftLocalTime;
    wchar_t * tempDir = NULL;

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
            myOsInfo->Processor = "x64 (AMD or Intel)";
            break;
        }
        case PROCESSOR_ARCHITECTURE_INTEL:
        {
            myOsInfo->Processor = "x32 (Intel)";
            break;
        }
        default:
        {
            myOsInfo->Processor = "Unknown";
        }
    }

    // setting number of processors
    myOsInfo->NumberOfProcessors = si.dwNumberOfProcessors;
    
    // getting windows version for this instance
    GetWindowsVersion(myOsInfo);

    // getting all windows services for this instance
    GetAllWindowsServices(&myOsInfo->services);

    myOsInfo->Win32Dir = _wcsdup(GetWindowsDir());

    tempDir = GetTempFolderPathWin32();

    myOsInfo->TempDir = _wcsdup(tempDir);

    // getting localtime
    GetSystemTimeAsFileTime(&ftSysTime);
    FileTimeToLocalFileTime(&ftSysTime, &ftLocalTime);

    myOsInfo->LocalTime = FileTimeUnixWin32(&ftLocalTime);


    // getting resources
    myOsInfo->resources = malloc(sizeof(resource_stats_t));
    collect_resource_stats(myOsInfo->resources);

    GetAdapters(myOsInfo);

    free(tempDir);

    return myOsInfo;
}

// frees internal data of services 
void clearServices(services_t * pack)
{
    for (int i = 0; i < pack->count; i++) {
        winservice_t * toBeCleared = &pack->data[i];
        if (!toBeCleared->denied) {

            // delete dynamically allocated name and description
            free(toBeCleared->name);
            free(toBeCleared->desc);
        } 
    }

    // delete array
    free(pack->data);
}

// frees internal data of adapters
void clearAdapters(adapters_t * aptr)
{
    for (int i = 0; i < aptr->size; i++) {

        adapterinfo_t * value = &aptr->data[i];
        if (value->name) {
            free(value->name);
        }
        if (value->desc) {
            free(value->desc);
        }
    }

    // delete array
    free(aptr->data);
}

void OSInfoFree(POSInfo * ptr)
{
    POSInfo real = (*ptr);

    if (real) {
        free(real->TempDir);
        free(real->Win32Dir);
        free(real->resources);
        clearServices(&real->services);
        clearAdapters(&real->adapters);
    }

    free(real);
}

void GetWindowsVersion(POSInfo value)
{
    OSVERSIONINFO osVer;
    ZeroMemory(&osVer, sizeof(OSVERSIONINFO));

    osVer.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    if (IsWindows10OrGreater()) { // never work without manifest :)
        value->WinMajor = 10;
    }
    else if (IsWindows8OrGreater()) {
        value->WinMajor = 8;
    } else if (IsWindows7OrGreater()) {
        value->WinMajor = 7;
    } else if (IsWindowsVistaOrGreater()) {
        value->WinMajor = 6;
    }

    if (IsWindowsServer()) {
        value->MachineType = "server";
    } else value->MachineType = "client";

    // also, getting minor version :)
    GetVersionEx(&osVer);

    value->WinMinor = osVer.dwMinorVersion;
    value->BuildNumber = osVer.dwBuildNumber;
}



int GetAllWindowsServices(services_t * pack)
{
    SC_HANDLE scm;          // handle to scmanager
    DWORD cbBytesNeeded;    // size of the buffer
    DWORD err;              // last error of winapi
    LONG  errFunc;          // last error of this function
    DWORD dwServiceCount;
    LPENUM_SERVICE_STATUS_PROCESS services;        // buffer where data of services to be stored
    services = NULL;
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

    LocalFree(services);
    CloseServiceHandle(scm);
    return SRETRIEVE_OK;
}

#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

int GetAdapters(POSInfo osPtr)
{
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    unsigned int i, j;

    /* variables used for GetIfTable and GetIfEntry */
    MIB_IFTABLE *pIfTable;
    MIB_IFROW *pIfRow;
    adapterinfo_t * allAdapters, * perAdapter;

    // Allocate memory for our pointers.
    pIfTable = (MIB_IFTABLE *) MALLOC(sizeof (MIB_IFTABLE));
    if (pIfTable == NULL) {
        printf("Error allocating memory needed to call GetIfTable\n");
        return 1;
    }
    // Make an initial call to GetIfTable to get the
    // necessary size into dwSize
    dwSize = sizeof (MIB_IFTABLE);
    if (GetIfTable(pIfTable, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        FREE(pIfTable);
        pIfTable = (MIB_IFTABLE *) MALLOC(dwSize);
        if (pIfTable == NULL) {
            printf("Error allocating memory needed to call GetIfTable\n");
            return 1;
        }
    }
    // Make a second call to GetIfTable to get the actual
    // data we want.
    if ((dwRetVal = GetIfTable(pIfTable, &dwSize, FALSE)) == NO_ERROR) {
        
        allAdapters = malloc(sizeof(adapterinfo_t) * pIfTable->dwNumEntries);
        
        // ! if no memory
        if (!allAdapters) {
            if (pIfTable != NULL) {
                FREE(pIfTable);
                pIfTable = NULL;
            }

            return 1;
        }

        perAdapter = allAdapters;
        // run through all adapters and assign info
        for (i = 0; i < pIfTable->dwNumEntries; i++) {
            pIfRow = (MIB_IFROW *) & pIfTable->table[i];
            
            if ((dwRetVal = GetIfEntry(pIfRow)) == NO_ERROR) {

                DWORD dwDescLen;
                UCHAR * desc; // alias for uint8_t on Windows
                perAdapter->name = NULL;
                perAdapter->desc = NULL;
                perAdapter->sent = 0;
                perAdapter->received = 0;
                perAdapter->speed = 0;

                // type of adapter
                perAdapter->type = pIfRow->dwType;
                
                // system name
                perAdapter->name = _wcsdup(pIfRow->wszName);
                
                // description
                // if len != 0
                if (pIfRow->dwDescrLen) {
                    
                    dwDescLen = pIfRow->dwDescrLen;
                    desc = malloc(dwDescLen + 1); // + 1 for NUL
                    if (desc) {

                        // better memcpy for unsigned bytes
                        memcpy(desc, pIfRow->bDescr, dwDescLen);
                        desc[dwDescLen] = '\0';
                        perAdapter->desc = desc;
                    }
                }

                // received octets
                perAdapter->received = pIfRow->dwInOctets;

                // sent octets
                perAdapter->sent = pIfRow->dwOutOctets;

                // speed
                perAdapter->speed = pIfRow->dwSpeed;

                // move to next
                perAdapter++;
            }
        }


        // assign data to main structure
        osPtr->adapters.data = allAdapters;
        osPtr->adapters.size = pIfTable->dwNumEntries;

    } else {

        if (pIfTable != NULL) {
            FREE(pIfTable);
            pIfTable = NULL;
        }  
        return 1;
    }
    if (pIfTable != NULL) {
        FREE(pIfTable);
        pIfTable = NULL;
    }
    return 0;
}