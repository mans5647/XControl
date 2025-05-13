#ifndef UNICODE
#define UNICODE
#endif

#include "win_process.h"
#include "util.h"
#include "win_misc.h"
#include "file_util.h"
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdlib.h>
#include <stdint.h>
#include <cJSON.h>
#include <NTSecAPI.h>
#include <ntstatus.h>


#define MAX_PROCESS USHRT_MAX
#define PROC_NAMELEN 500
#define MIN_PROCESS_CAP 10

#define MS_TIME_EPOCH   116444736000000000LL
#define NS_UNIT         10000000LL
#define MILLIS          10000


static int64_t filetime2unix(const FILETIME * ft)
{
    int64_t utime = 0;
    
    ULARGE_INTEGER bigInt;

    bigInt.HighPart = ft->dwHighDateTime;
    bigInt.LowPart = ft->dwLowDateTime;
    utime = ((int64_t)(bigInt.QuadPart) - MS_TIME_EPOCH) / NS_UNIT;
    return (int64_t)utime;
}

static TCHAR * GetProcessUserName(HANDLE pToken)
{
    TOKEN_USER info;
    DWORD nameLen = MAX_PATH;
    TCHAR * bufUserName = NewMemory(TCHAR, MAX_PATH);
    
    ZeroMemory(&info, sizeof(TOKEN_USER));
    DWORD cb = 0;
    if (!GetTokenInformation(pToken, TokenUser, NULL, 0, &cb)) {
        
        if (ERROR_INSUFFICIENT_BUFFER == GetLastError()) {
            PTOKEN_USER user = (PTOKEN_USER)LocalAlloc(0, cb);
            if (GetTokenInformation(pToken, TokenUser, user, cb, &cb)) {
                
                SID_NAME_USE sidNameUse;
                WCHAR domain[MAX_PATH];
                DWORD dSize = MAX_PATH;
                if (LookupAccountSid(nil, user->User.Sid, bufUserName, &nameLen, domain, &dSize, &sidNameUse)) {
                    LocalFree(user);
                    return (TCHAR*)bufUserName;
                } else {
                    LocalFree(user);
                    free(bufUserName);
                    return _wcsdup(L"<unknown>");
                }
            }
            LocalFree(user);

        }

    }

    FreeMemoryBlock(bufUserName);

    return NULL;
}


WinProcess * RetrieveAllProcesses(len_t * count, len_t * wr_cap)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        (*count) = 0;
        return NULL;
    }
    
    len_t cap = MIN_PROCESS_CAP;
    

    WinProcess * data = AllocCount(WinProcess, cap);

    PROCESSENTRY32 pEntry;
    pEntry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &pEntry)) {
        (*count) = 0;
        free(data);
        CloseHandle(snapshot);
        return NULL;
    }

    WinProcess * iterator = data;

    len_t counter = 0;
    
    do
    {

        if (counter >= cap) {
            const len_t ncap = cap + MIN_PROCESS_CAP;
            data = DataReallocCount(WinProcess, ncap, data);
            cap = ncap;
            iterator = (data + counter);
        }

        iterator->accessOk =        true;
        iterator->CreationTime =    -1;
        iterator->UserTime =        -1;
        iterator->Name =            NULL;
        iterator->UserName =        NULL;
        iterator->Path =            NULL;
        iterator->WorkingSetSize =  0;
        
        
        size_t szOfExeFile = 0;

        #ifdef UNICODE
            szOfExeFile = wcslen(pEntry.szExeFile);
            iterator->Name = CreateStringFromWideChars(pEntry.szExeFile, szOfExeFile);
        #else
            szOfExeFile = strlen(pEntry.szExeFile);
            iterator->Name = CreateString(pEntry.szExeFile, szOfExeFile, US_ASCII);
        #endif

        iterator->Id = pEntry.th32ProcessID;
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pEntry.th32ProcessID);

        if (hProcess != NULL) {

            PROCESS_MEMORY_COUNTERS pMemStat = {0};
            pMemStat.cb = sizeof(pMemStat);
            FILETIME createTime, userTime, p1, p2;
            if (GetProcessMemoryInfo(hProcess, &pMemStat, sizeof(pMemStat)))
            {
                iterator->WorkingSetSize = pMemStat.WorkingSetSize;
            }

            DWORD exBufSize = MAX_PATH;
            TCHAR imgName[MAX_PATH] = {0};

            if (QueryFullProcessImageName(hProcess, 0, imgName, &exBufSize)) {
                
                #ifdef UNICODE
                    imgName[exBufSize] = L'\0';
                    iterator->Path = CreateStringFromWideChars(imgName, exBufSize);
                #else
                    imgName[exBufSize] = 0;
                    iterator->Name = CreateString(imgName, exBufSize, US_ASCII);
                #endif
                
            }

            if (GetProcessTimes(hProcess, &createTime, &p1, &p2, &userTime)) {
                iterator->CreationTime = filetime2unix(&createTime);
            }
            
            HANDLE pToken = NULL;
            if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &pToken)) {
                PTCHAR process_user_name = GetProcessUserName(pToken);
                
                if (process_user_name) {
                    
                    #ifdef UNICODE
                        iterator->UserName = CreateStringFromWideChars(process_user_name, wcslen(process_user_name));
                    #else 
                        iterator->UserName = CreateString(process_user_name, strlen(process_user_name), US_ASCII);
                    #endif

                    free(process_user_name);
                }
                
                CloseHandle(pToken);
            }


            CloseHandle(hProcess);
        }

        ++counter;
        ++iterator;
        
    } while (Process32Next(snapshot, &pEntry));
    
    CloseHandle(snapshot);

    (*wr_cap) = cap;
    (*count) = (len_t)counter;
    return data;
}

void DestroyAllProcesses(WinProcess * ptr, len_t count)
{
    
    if (count > 0) {

        for (size_t i = 0; i < count; i++)
        {
            StringDestroy(ptr[i].Name);
            StringDestroy(ptr[i].Path);
            StringDestroy(ptr[i].UserName);
        }

        free(ptr);
    }

}

void * GetNewArray(void * data, size_t * cap, const size_t size)
{
    if (size >= *cap) {
        const size_t ncap = (*cap) * 2;
        data = realloc(data, ncap);
        if (!data) return NULL;
        (*cap) = ncap;
        return data;
    }

    return data;
}



#define NullOrElse(value, def) value ? value : def

char* WinProcessToJson (const WinProcess * data, len_t size)
{
    cJSON * arr = cJSON_CreateArray();
    const WinProcess * nextValue = data;
    while (size)
    {
        
        cJSON * process_object = cJSON_CreateObject();
        
        byte * nameStr = GetNullTerminatedBytes(nextValue->Name);
        byte * usernameStr = GetNullTerminatedBytes(nextValue->UserName);
        byte * pathStr = GetNullTerminatedBytes(nextValue->Path);
        
        cJSON_AddNumberToObject(process_object, "process_id", (double)nextValue->Id);
        cJSON_AddStringToObject(process_object, "process_name", nameStr);
        cJSON_AddStringToObject(process_object, "process_path", pathStr);
        cJSON_AddStringToObject(process_object, "process_user_name", usernameStr);
        cJSON_AddNumberToObject(process_object, "process_working_set", (double)nextValue->WorkingSetSize);
        cJSON_AddNumberToObject(process_object, "process_create_time", (double)nextValue->CreationTime);
        cJSON_AddNumberToObject(process_object, "process_user_time", (double)nextValue->UserTime);

        cJSON_AddItemToArray(arr, process_object);
        free(nameStr);
        free(usernameStr);
        free(pathStr);

        nextValue++;
        size--;
    }

    byte * str = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);

    return str;

}

void * GetPolicyHandle()
{
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS ntsResult;
    LSA_HANDLE lsahPolicyHandle;

    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
    // Get a handle to the Policy object.
    ntsResult = LsaOpenPolicy(
        NULL,         //Name of the target system.
        &ObjectAttributes,      //Object attributes.
        POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT,    //Desired access permissions.
        &lsahPolicyHandle       //Receives the policy handle.
    );

    if (ntsResult != STATUS_SUCCESS)
    {
        // An error occurred. Display it as a win32 error code.
        wprintf(L"OpenPolicy returned %lu\n",
        LsaNtStatusToWinError(ntsResult));
        return NULL;
    } 

    return (void*)lsahPolicyHandle;
}
void ClosePolicyHandle(void * handle)
{
    LsaClose((LSA_HANDLE)handle);
}

#define WcharLiteral(text) L##text

wchar_t* GetCurrentUserName(size_t * chars)
{
    DWORD cChars = MAX_PATH;
    PTCHAR buf = AllocCount(TCHAR, cChars);
    if (!GetUserName(buf, &cChars)) {
        return NULL;
    }

    buf[cChars] = WcharLiteral('\n');
    (*chars) = cChars;
    return buf;
}


boolean InitLsaString(
    PLSA_UNICODE_STRING pLsaString,
    PTCHAR pwszString
  )
  {
    DWORD dwLen = 0;
  
    if (NULL == pLsaString)
        return FALSE;
  
    if (NULL != pwszString) 
    {
        #ifdef UNICODE
            dwLen = (DWORD)wcslen(pwszString);
        #else
            dwLen = strlen(pwszString);
        #endif
        if (dwLen > 0x7ffe)   // String is too large
            return FALSE;
    }
  
    // Store the string.
    pLsaString->Buffer = (PWCHAR)pwszString;
    pLsaString->Length =  (USHORT)dwLen * sizeof(WCHAR);
    pLsaString->MaximumLength= (USHORT)(dwLen+1) * sizeof(WCHAR);
  
    return TRUE;
  }

boolean EnableDebugPrivelege(void* policy, void * userSid)
{
    LSA_UNICODE_STRING d;

    if (!InitLsaString(&d, SE_DEBUG_NAME))
    {
        return false;
    }
    
    NTSTATUS st = LsaAddAccountRights(policy, userSid, &d, 1);

    if (st == STATUS_SUCCESS) return true;
    DWORD err = LsaNtStatusToWinError(st);
    return (err == NO_ERROR);
}

void EnumAllPrivileges(void * pHandle, void * acc_sid)
{
    PLSA_UNICODE_STRING rights = AllocCount(LSA_UNICODE_STRING, 200);
    DWORD cnt = 0;
    (void)LsaEnumerateAccountRights(pHandle, acc_sid, &rights, &cnt);

}

boolean WINAPI TurnComputerOffWin32()
{
    return (boolean)ExitWindowsEx(EWX_POWEROFF, SHTDN_REASON_MAJOR_APPLICATION);
}

void WINAPI BlockInputWin32(boolean lock)
{
    if (lock) {
        BlockInput(TRUE);
    } else {
        BlockInput(FALSE);
    }
    
}

uint32_t GetLastErrorWin32()
{
    return GetLastError();
}

void SetLastErrorWin32(uint32_t c)
{
    SetLastError(c);
}

void SetNoErrorWin32()
{
    SetLastError(ERROR_SUCCESS);
}

boolean HasErrorWin32()
{
    return GetLastErrorWin32() != ERROR_SUCCESS;
}

time_t GetRunningTime()
{
    return (time_t)(GetTickCount64() / CLOCKS_PER_SEC);
}

#undef UNICODE
#define UNICODE 0

char * GetDesktopName()
{
    DWORD maxName = MAX_PATH;
    #if UNICODE == 1
        PWCHAR name = AllocCount(WCHAR, maxName);
        DWORD err = GetComputerNameW(name, &maxName);
        return (err == 0) ? NULL : (char*)name;
    #else
        char * name = AllocCount(char, maxName);
        DWORD err = GetComputerNameA(name, &maxName);
        return (err == 0) ? NULL : name;
    #endif
}

#undef UNICODE
#define UNICODE 1


char* CaptureScreen_impl(HWND hWnd, size_t* SizeInBytes)
{
    HDC hdcScreen = NULL;
    HDC hdcMemDC = NULL;
    HBITMAP hbmScreen = NULL;
    BITMAP bmpScreen;
    DWORD dwBmpSize = 0;
    DWORD dwSizeofDIB = 0;
    char* lpbitmap = NULL;
    char* bmpBuffer = NULL;
    HANDLE hDIB = NULL;

    // Get screen dimensions
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    // Get the device context of the entire screen
    hdcScreen = GetDC(NULL);
    hdcMemDC = CreateCompatibleDC(hdcScreen);
    if (!hdcMemDC) {
        MessageBox(hWnd, L"CreateCompatibleDC has failed", L"Failed", MB_OK);
        goto done;
    }

    // Create a compatible bitmap of the entire screen
    hbmScreen = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
    if (!hbmScreen) {
        MessageBox(hWnd, L"CreateCompatibleBitmap Failed", L"Failed", MB_OK);
        goto done;
    }

    SelectObject(hdcMemDC, hbmScreen);

    // Copy screen content into memory DC
    if (!BitBlt(hdcMemDC, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY)) {
        MessageBox(hWnd, L"BitBlt has failed", L"Failed", MB_OK);
        goto done;
    }

    // Get bitmap info
    GetObject(hbmScreen, sizeof(BITMAP), &bmpScreen);

    BITMAPFILEHEADER bmfHeader;
    BITMAPINFOHEADER bi = { 0 };

    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = bmpScreen.bmWidth;
    bi.biHeight = bmpScreen.bmHeight;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;
    bi.biSizeImage = 0;
    bi.biXPelsPerMeter = 0;
    bi.biYPelsPerMeter = 0;
    bi.biClrUsed = 0;
    bi.biClrImportant = 0;

    dwBmpSize = ((bmpScreen.bmWidth * bi.biBitCount + 31) / 32) * 4 * bmpScreen.bmHeight;
    dwSizeofDIB = dwBmpSize + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

    hDIB = GlobalAlloc(GHND, dwBmpSize);
    if (!hDIB) goto done;
    lpbitmap = (char*)GlobalLock(hDIB);

    if (!GetDIBits(hdcMemDC, hbmScreen, 0, (UINT)bmpScreen.bmHeight, lpbitmap, (BITMAPINFO*)&bi, DIB_RGB_COLORS)) {
        MessageBox(hWnd, L"GetDIBits failed", L"Failed", MB_OK);
        goto done;
    }

    bmpBuffer = malloc(dwSizeofDIB);
    if (!bmpBuffer) goto done;

    bmfHeader.bfType = 0x4D42;
    bmfHeader.bfSize = dwSizeofDIB;
    bmfHeader.bfReserved1 = 0;
    bmfHeader.bfReserved2 = 0;
    bmfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

    memcpy(bmpBuffer, &bmfHeader, sizeof(BITMAPFILEHEADER));
    memcpy(bmpBuffer + sizeof(BITMAPFILEHEADER), &bi, sizeof(BITMAPINFOHEADER));
    memcpy(bmpBuffer + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER), lpbitmap, dwBmpSize);

    *SizeInBytes = dwSizeofDIB;

done:
    if (hDIB) {
        GlobalUnlock(hDIB);
        GlobalFree(hDIB);
    }
    if (hdcScreen) ReleaseDC(NULL, hdcScreen);
    if (hdcMemDC) DeleteDC(hdcMemDC);
    if (hbmScreen) DeleteObject(hbmScreen);

    return bmpBuffer;
}




HWND GetWindowHandle();

#define USE_ACTIVE_WIN 0
#if USE_ACTIVE_WIN
    HWND GetWindowHandle()
    {
        return GetActiveWindow();
    }
#else
    HWND GetWindowHandle()
    {
        return GetConsoleWindow();
    }
#endif

char * CaptureScreen(size_t * bytes)
{
    HWND wnd = GetWindowHandle();
    if (!wnd) return NULL;
    return CaptureScreen_impl(wnd, bytes);
}


void * CreateFileWin32(const wchar_t* fileName)
{
    return (void*)CreateFileW(
        fileName, 
        GENERIC_WRITE, 
        FILE_SHARE_READ, 
        NULL, 
        CREATE_ALWAYS, 
        FILE_ATTRIBUTE_NORMAL, 
        NULL);
}


boolean IsFileValidWin32(const void * handle)
{
    return ((const HANDLE)handle) != INVALID_HANDLE_VALUE;
}

uint32_t WriteFileWin32(const void * data, uint32_t length, void * file)
{
    DWORD written = 0;
    
    WriteFile(file, data, length, &written, NULL);
    
    return written;
}

uint32_t WriteFileWin32_ascii(char value, void * file)
{
    return WriteFileWin32(&value, sizeof(char), file);
}

uint32_t WriteFileWin32_unicode(const wchar_t value, void * file)
{
    return WriteFileWin32(&value, sizeof(wchar_t), file);
}

void CloseFileWin32(void * file)
{
    CloseHandle(file);
}

boolean IsFileExistsWin32(const wchar_t * fileName)
{
    DWORD value = GetFileAttributes(fileName);

    return (value != INVALID_FILE_ATTRIBUTES);
}

void * OpenFileWithAppendWin32(const wchar_t * filename)
{
    return CreateFile(filename, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
}

void * OpenFileWin32(const wchar_t* filename)
{
    return CreateFile(filename, FILE_APPEND_DATA | FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
}

size_t filesize_as_GetFileSizeWin32_internal(HANDLE file)
{
    DWORD dwHighPart = 0, dwSize = 0;
    DWORD dwLowPart = GetFileSize(file, &dwHighPart);
    
    if (dwLowPart != INVALID_FILE_SIZE) {
        
        dwSize = ((dwHighPart << 32) | dwLowPart);
    }

    if (dwSize >= ULONG_MAX) {
        dwSize = 0;
    }

    return dwSize;
}

size_t filesize_as_offset_win32_internal(HANDLE file)
{
    size_t sz = 0;
    LONG dwHigh = 0;
    DWORD dwLow = SetFilePointer(file, 0, &dwHigh, FILE_END);
    
    if (dwLow != INVALID_SET_FILE_POINTER) {

        sz = (((size_t)dwHigh) << 32) | dwLow;
    }

    return sz;
}

char * ReadFileAllWin32(void * fileHandle, size_t * out_siz)
{
    size_t dwSize = 0;

    dwSize = filesize_as_GetFileSizeWin32_internal(fileHandle);

    char * data = malloc(dwSize);

    if (!data) {
        (*out_siz) = 0;
        return NULL;
    }

    if (ReadFile(fileHandle, data, (DWORD)dwSize, NULL, NULL)) {
        (*out_siz) = dwSize;
        return data;
    }

    free(data);
    return NULL;
}

wchar_t * GetTempFolderPathWin32()
{
    DWORD length = MAX_PATH + 1, copied;
    WCHAR * path = AllocCount(WCHAR, length);
    
    copied = GetTempPathW(length, path);

    if (copied > ZERO) {
        path[copied] = '\0';
        return path;
    }

    free(path);
    return NULL;
}

wchar_t * GetWindowsDir()
{ 
    static wchar_t winDir[MAX_PATH];
    DWORD dwCopied = GetWindowsDirectory(winDir, MAX_PATH);
    if (dwCopied) {
        winDir[dwCopied] = L'\0';
        return winDir;
    }

    return NULL;
}

unix_time_t FileTimeUnixWin32(void *ft)
{
    uint64_t winTime;
    unix_time_t value;
    LPFILETIME lpFileTime = ft;
    ULARGE_INTEGER q;
    q.HighPart = lpFileTime->dwHighDateTime;
    q.LowPart = lpFileTime->dwLowDateTime;
    winTime = q.QuadPart;
    value = ((winTime) / 10000000) - 11644473600LL;

    return value;
}

int32_t Win32WriteStdout(const char * data)
{
    size_t numBytes = strlen(data);
    WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), data, numBytes, NULL, NULL);
}

int32_t Win32WriteUnicode(const wchar_t * data)
{
    size_t numBytes = wcslen(data);
    WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), data, numBytes, NULL, NULL);
}

/* processes defs */
struct ProcessExecutePostState
{
    int exit; // process exit code
    int stream_type; // (stdout or stderr)
    fbuf_t buffer; // buffer holds data
};

typedef struct ProcessExecutePostState* PepPtr;

struct ProcessExecutePostState* PEPStateCreate()
{
    PepPtr state;
    if ((state = malloc(sizeof(struct ProcessExecutePostState))) == NULL) {
        return NULL;
    }

    if (fbuf_init2(&state->buffer)) {
        return NULL;
    }

    state->exit = 0;
    state->stream_type = PEP_STDOUT;

    return state;

}
void                           PEPStateDestroy(struct ProcessExecutePostState * pep)
{
    // ! note, dealloc dynamic pointer

    if (pep) {
        fbuf_clear(&pep->buffer);
    }
    free(pep);
}
int                            PEPStateGetExitCode(struct ProcessExecutePostState * pep)
{
    return pep->exit;
}
int                            PEPStateGetStream(struct ProcessExecutePostState* pep)
{
    return pep->stream_type;
}
fbuf_ptr                       PEPStateGetBuffer(struct ProcessExecutePostState* pep)
{
    return &pep->buffer;
}


#define PIPE_RBUF_SIZE 100000
#define PIPE_WBUF_SIZE 100000
#define PIPE_INSTANCES 12

BOOL CreateAsyncPipes(CONST PTCHAR name, PHANDLE stdoutReader, PHANDLE stdoutWriter)
{
    HANDLE pipeReader;
    HANDLE pipeWriter;
    SECURITY_ATTRIBUTES saAttr = {0};
    
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);

    pipeReader = CreateNamedPipe(
        name, 
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_INSTANCES,
        PIPE_WBUF_SIZE, PIPE_RBUF_SIZE, NMPWAIT_USE_DEFAULT_WAIT, &saAttr);

    if (pipeReader == INVALID_HANDLE_VALUE) {
        printf("CreateNamedPipe (read): %d\n", GetLastError());
        return FALSE;
    }


    

    pipeWriter = CreateFile(name, GENERIC_WRITE, 0, &saAttr, OPEN_EXISTING, 0, 0);

    if (pipeWriter == INVALID_HANDLE_VALUE) {
        printf("CreateNamedPipe (write): %d\n", GetLastError());
        return FALSE;
    }

    *stdoutReader = pipeReader;
    *stdoutWriter = pipeWriter;
    return TRUE;
}

// write's to process STDIN
boolean WriteToPipe(CState* consoleState, const wchar_t* buffer)
{
    // Convert wide-character input to ANSI
    char ansiBuffer[512];
    int ansiLen = WideCharToMultiByte(CP_ACP, 0, buffer, -1, ansiBuffer, sizeof(ansiBuffer), NULL, NULL);
    if (ansiLen == 0) {
        return false;
    }
    ansiLen--; // Exclude null terminator

    // Write the command
    DWORD dwWritten;
    BOOL bSuccess = WriteFile(consoleState->in_writer, ansiBuffer, ansiLen, &dwWritten, NULL);
    if (!bSuccess) {
        return false;
    }


    // Write CRLF to simulate Enter
    const char crlf[] = "\r\n";
    bSuccess = WriteFile(consoleState->in_writer, crlf, sizeof(crlf) - 1, &dwWritten, NULL);
    if (!bSuccess || dwWritten != sizeof(crlf) - 1) {
        return false;
    }

    return true;
}
// reads process's stdout and writes to output
boolean ReadFromPipe(CState * console, fbuf_ptr outBuf)
{
    DWORD dwRead;
    BOOL bSuccess = FALSE;
    CHAR chBuf[PIPE_RBUF_SIZE];

    for (;;)
    {
        DWORD dwBytesAvailable = 0;

        // Peek to check if there's anything to read
        if (!PeekNamedPipe(console->out_reader, NULL, 0, NULL, &dwBytesAvailable, NULL)) {
            return false; // Pipe error
        }

        if (dwBytesAvailable == 0) {
            return false;
        }

        bSuccess = ReadFile(console->out_reader, chBuf, min(PIPE_RBUF_SIZE, dwBytesAvailable), &dwRead, NULL);
        if (!bSuccess || dwRead == 0) {
            break;
        }

        if (outBuf != NULL) {
            fbuf_append(outBuf, chBuf, dwRead);
        }
    }

    return true;
}



#define USE_NAMED_PIPES 1

boolean CreateNewConsole(CState * ctx)
{
    SECURITY_ATTRIBUTES saAttr = {0};
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    BOOL bSuccess = FALSE;
    TCHAR szCmdLine[] = TEXT("cmd.exe /k \"@echo off && chcp 65001 2>&1 >nul\"");

    HANDLE stdinReader = NULL;
    HANDLE stdinWriter = NULL;
    HANDLE stdoutReader = NULL;
    HANDLE stdoutWriter = NULL;

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.lpSecurityDescriptor = NULL;
    saAttr.bInheritHandle = TRUE;

    #if USE_NAMED_PIPES
        // create pipes for stdout (read and write)
        if (!CreateAsyncPipes(L"\\\\.\\pipe\\ConsoleStdout", &stdoutReader, &stdoutWriter)) {
            printf("CreateAsyncPipes (stdout): %d\n", GetLastError());
            return false;
        }

        // create pipes for stdin (read and write)

        if (!CreateAsyncPipes(L"\\\\.\\pipe\\ConsoleStdin", &stdinReader, &stdinWriter)) {
            printf("CreateAsyncPipes (stdin): %d\n", GetLastError());
            return false;
        }
    #else
        // Create a pipe for the child process's STDOUT. 
 
        if (!CreatePipe(&stdoutReader, &stdoutWriter, &saAttr, 0) ) 
            return false;

        // Ensure the read handle to the pipe for STDOUT is not inherited.

        if (!SetHandleInformation(stdoutReader, HANDLE_FLAG_INHERIT, 0) )
            return false;

        // Create a pipe for the child process's STDIN. 

        if (!CreatePipe(&stdinReader, &stdinWriter, &saAttr, 0)) 
            return false;


        // Ensure the write handle to the pipe for STDIN is not inherited. 

        if (!SetHandleInformation(stdinWriter, HANDLE_FLAG_INHERIT, 0) )
            return false;
    #endif

    
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFO) );

    
    si.cb = sizeof(STARTUPINFO);
    si.lpTitle = TEXT("i/o");
    si.hStdInput = stdinReader;
    si.hStdError = stdoutWriter;
    si.hStdOutput = stdoutWriter;
    si.dwFlags |= STARTF_USESTDHANDLES;

    bSuccess = CreateProcess(
        NULL,
        szCmdLine, 
        NULL,           // process security attributes 
        NULL,           // primary thread security attributes 
        TRUE,           // handles are inherited 
        0,              // creation flags 
        NULL,           // use parent's environment 
        NULL,           // use parent's current directory 
        &si,            // STARTUPINFO pointer 
        &pi);           // PROCESS_INFORMATION pointer
    
    if (!bSuccess) {
        printf("CreateProcess last error: %d\n", GetLastError());
        return false;
    }
    ctx->error_code = 0;
    ctx->process = pi.hProcess;
    ctx->console_thread = pi.hThread;
    ctx->out_reader = stdoutReader;
    ctx->out_writer = stdoutWriter;
    ctx->in_reader = stdinReader;
    ctx->in_writer = stdinWriter;
    ctx->mutex = CreateMutex(NULL, FALSE, NULL);
    
    if (ctx->mutex == NULL) {
        printf("CreateMutex last error: %d\n", GetLastError());
        return false;
    }

    
    return true;
}

boolean ConsoleMutexLock(CState * console)
{
    return WaitForSingleObject(console->mutex, INFINITE) > 0;
}
BOOL ConsoleMutexUnlockWin32(CState * console)
{
    return ReleaseMutex(console->mutex);
}

boolean ConsoleMutexUnlock(CState * console)
{
    return ConsoleMutexUnlockWin32(console) != FALSE;
}

DWORD AvailableToRead(CState * console)
{
    DWORD dwAvailableBytes = 0;

    if (!PeekNamedPipe(console->out_reader, NULL, 0, NULL, &dwAvailableBytes, NULL)) {
        return 0;
    }

    return dwAvailableBytes;
}

fbuf_ptr ExecuteCommandInConsole(CState * ctx, wchar_t * command)
{
    /*lock*/
    ConsoleMutexLock(ctx);
    fbuf_ptr buf = NULL;
    buf = fbuf_new_with_size(0);
    WriteToPipe(ctx, command);

    /* wait for data is become available */
    while (AvailableToRead(ctx) == 0) {
        Sleep(1000);
    }

    /* read until data is not available */
    while (ReadFromPipe(ctx, buf));

    ConsoleMutexUnlock(ctx);
    return buf;
}


void CloseConsole(CState * ctx)
{
    TerminateProcess(ctx->process, 0);
    CloseHandle(ctx->process);
    CloseHandle(ctx->console_thread);
    CloseHandle(ctx->out_reader);
    CloseHandle(ctx->out_writer);
    CloseHandle(ctx->in_reader);
    CloseHandle(ctx->in_writer);
}

/* processes defs end */


/*
misc string begin
*/

typedef struct {
	char mask;    /* char data will be bitwise AND with this */
	char lead;    /* start bytes of current char in utf-8 encoded character */
	uint32_t beg; /* beginning of codepoint range */
	uint32_t end; /* end of codepoint range */
	int bits_stored; /* the number of bits from the codepoint that fits in char */
}utf_t;

utf_t utf[] = {
	/*             mask        lead        beg      end       bits */
	[0] = {0b00111111, 0b10000000, 0,       0,        6    },
	[1] = {0b01111111, 0b00000000, 0000,    0177,     7    },
	[2] = {0b00011111, 0b11000000, 0200,    03777,    5    },
	[3] = {0b00001111, 0b11100000, 04000,   0177777,  4    },
	[4] = {0b00000111, 0b11110000, 0200000, 04177777, 3    },
        {0},
};

/* length of utf8 encoded string in bytes */
size_t UTF8_Size(const char * s)
{
    size_t strsize = 0;
    int i = 0;
	for (;;) {
        const char * ch = &s[i];
        if (*ch == '\0') break;
        int len = 0;
        for(utf_t * u = &utf[0]; u != 0; ++u) {
            if((*ch & ~u->mask) == u->lead) {
                break;
            }
            ++len;
        }

        i += len;
    }
	
	return i;
}

/*
@brief Converts UTF-8 string into UTF-16 string
@param uu UTF8 bytes
@param bytes size in bytes!
*/
wchar_t * UTF8BytesToWide(const char* uu, int32_t bytes)
{
    DWORD dwUtf16Required, dwUtf16Copied;
    wchar_t * buf;
    dwUtf16Required = MultiByteToWideChar(CP_UTF8, 0, uu, -1, NULL, 0);

    buf = malloc(sizeof(wchar_t) * dwUtf16Required);
    if (!buf) return NULL;
    
    dwUtf16Copied = MultiByteToWideChar(CP_UTF8, 0, uu, -1, buf, dwUtf16Required);

    if (dwUtf16Copied) {
        return buf;
    }
    printf("<!> UTF8BytesToWide, GetLastError: %lu\n", GetLastErrorWin32());
    return NULL;
}

/*
misc string end
*/


boolean IsUtfCodePage()
{
    return GetACP() == CP_UTF8;
}
boolean IsWideCodePage()
{
    return GetACP() == CP_ACP;
}