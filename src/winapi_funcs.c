#ifndef UNICODE
#define UNICODE
#endif

#include "win_process.h"
#include "util.h"
#include "win_misc.h"
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
    return CreateFile(filename, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
}

size_t filesize_as_GetFileSizeWin32_internal(HANDLE file)
{
    size_t dwHighPart, dwSize;
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
    size_t dwSize;

    dwSize = filesize_as_GetFileSizeWin32_internal(fileHandle);

    char * data = AllocCount(char, dwSize);

    if (!data) {
        (*out_siz) = 0;
        return NULL;
    }

    if (ReadFile(fileHandle, (LPVOID)data, (DWORD)dwSize, NULL, NULL)) {
        (*out_siz) = dwSize;
        return data;
    }

    free(data);
    return NULL;
}

wchar_t * GetTempFolderPathWin32()
{
    DWORD length = MAX_PATH + 1;
    WCHAR * path = AllocCount(WCHAR, length);
    if (GetTempPathW(length, path) > ZERO) {
        path[length] = L'\0';
        return path;
    }

    free(path);
    return NULL;
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