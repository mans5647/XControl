#ifndef PROXY_I
#define PROXY_I
#include <stdint.h>
#include <limits.h>

#define HTTP_SCHEME "http://"
#define PROXY_PORT ":10013"            // docker expose address

#define ERR_CONN_FAILED 1
#define ERR_NO_DATA 2
#define INVALID_ID  LONG_MIN

struct client;

typedef struct client * pclient_t;

int     PostOSInfo(void* arg);
int     PostProcesses(void * arg);
int     PollAboutCommand(void * arg);
pclient_t RegisterClient();
int     ClientKeepAlive(void *ctx);
void    ClientFree(pclient_t value);
long    ClientGetID(pclient_t);
#endif