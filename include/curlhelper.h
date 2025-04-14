#ifndef CURL_HELPER
#define CURL_HELPER


typedef void CURL;
typedef enum CURLcode CURLcode;

struct Buffer
{
    char * data;
    size_t size;
};

typedef struct HttpClient
{
    CURL * handle;
    CURLcode last_error;
    struct curl_slist * headers;
    struct Buffer * buf;

} HttpClient;

void AddHeader(HttpClient * const p, void * buf);
HttpClient * NewSSLClient();
void HttpClientFree(HttpClient * p);
void HttpClientReset(HttpClient ** p);
void HttpClientPerform(HttpClient * const c);
boolean HttpClientHasError(const HttpClient * c);
HttpClient * HttpClientSetUrl(HttpClient * cl, const char * u);
char * HttpClientGetData(HttpClient * c);
HttpClient * HttpClientSetDataSent(HttpClient * c, char * data, size_t dat_size, boolean);
HttpClient * HttpClientSetOnlyRequestBody(HttpClient * c, char * data, size_t dat_size, boolean put);
HttpClient * HttpClientSetMethod(HttpClient * c, const char * m);
void HttpClientResetBody(HttpClient * c);
long HttpClientGetResponseCode(const HttpClient * c);   
void HttpClientSetHeadMethod(HttpClient * c);
#endif CURL_HELPER