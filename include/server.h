#ifndef SERVER_H
#define SERVER_H 1

#include "types.h"


#define ServerErrorNoError 0
#define ServerEventError 1
#define ServerInternalError 2
#define ServerBindError 3
#define ServerListerError 4

#define PATH_FLAG_ACCESS_ALL    0x00
#define PATH_FLAG_AUTH_REQUIRED 0x02
#define PATH_FLAG_FORBIDDEN     0x04

#define STATUS_BLOCKED 1
#define STATUS_OPEN 0

#define HTTP_POST "POST"
#define HTTP_GET "GET"


#define HTTP_CODE_FORBIDDEN 403
#define HTTP_CODE_CREATED 201

#define MIME_JSON "application/json; charset=UTF-8"
#define MIME_TEXT_PLAIN "text/plain; charset=UTF-8"
#define OCTET_STREAM "application/octet-stream"

#define HTTP_HEADER_CT "Content-Type"

typedef enum HttpPathCallbackType
{
    TOsInfoCallback = 0,
    TBlockInputCallback = 1,
    TShutdownSystemCallback = 2,
    TProcesses = -99,
    TCpuMemory,
    TKeyBoardLog,
} HttpPathCallbackType;

struct evhttp_request;

typedef void (*http_os_info_callback)(struct evhttp_request *);
typedef void (*http_block_uinput_callback)(struct evhttp_request*);
typedef void (*http_shutdown_system_cb)(struct evhttp_request*, void*);
typedef void (*http_action_cb)(struct evhttp_request*, HttpPathCallbackType, void*);

struct http_path
{
    const char * path;
    integer_t status;
    const char * method;
    ushort_t flags;
    union {
        http_os_info_callback GetOsInfoCallback;
        http_block_uinput_callback BlockUserInputCallback;
        http_shutdown_system_cb ShutdownSystemCallback;
        http_action_cb GenericCallback;
    };

    HttpPathCallbackType cb_type;
};

typedef struct http_path http_path_t;


boolean CheckClient();
boolean InitializeWSock();
void    DetachWSock();
integer_t RunServer(ushort_t port, const char* address);
void TestEvent();
void StopHttpServer(integer_t fd);

#endif