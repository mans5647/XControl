
#define _CRT_SECURE_NO_WARNINGS

#include <stdlib.h>
#include <stdint.h>
#include "types.h"
#include "my_string.h"
#include "curlhelper.h"
#include "win_misc.h"
#include <curl/curl.h>

#define INIT_SIZE   200
#define MAX_SIZE    255

static size_t write_cb_addr(char *data, size_t size, size_t nmemb, void *clientp)
{
    struct Buffer * buf = (struct Buffer*)clientp;

    size_t realsize = size * nmemb;

    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if(!ptr)
        return 0;  /* out of memory */

    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), data, realsize);
    buf->size += realsize;
    buf->data[buf->size] = '\0';

    return realsize;
}



char * user_agent_curl()
{
    const curl_version_info_data* info = curl_version_info(CURLVERSION_NOW);
    char * data = (char*)malloc(MAX_SIZE * sizeof(char));
    sprintf(data, "curl/%s", info->version); 
    return data;
}

void AddHeader(HttpClient * const p, void * buf)
{
    p->headers = curl_slist_append(p->headers, (const char*)buf);
}


HttpClient * NewSSLClient()
{
    static const char *pCertFile = "cert.pem";
    
    HttpClient * cl = malloc(sizeof(HttpClient));
    cl->handle = curl_easy_init();
    if (!cl->handle) 
    {
        free(cl);
        return NULL;
    }

    cl->headers = NULL;
    cl->last_error = CURLE_OK;
    cl->buf = malloc(sizeof(struct Buffer));
    cl->buf->data = NULL;
    cl->buf->size = 0;

    char * ua = user_agent_curl();
    curl_easy_setopt(cl->handle, CURLOPT_USERAGENT, ua);
    curl_easy_setopt(cl->handle, CURLOPT_CAINFO, pCertFile);
    curl_easy_setopt(cl->handle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(cl->handle, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(cl->handle, CURLOPT_WRITEFUNCTION, write_cb_addr);
    curl_easy_setopt(cl->handle, CURLOPT_WRITEDATA, (void *)cl->buf);
    free(ua);
    return cl;
}

void HttpClientFree(HttpClient * p)
{
    if (p) {    
        curl_easy_cleanup(p->handle);
        curl_slist_free_all(p->headers);
        
        if (p->buf) {
            free(p->buf->data);
        }
        
        free(p->buf);
    }

    free(p);
}

void HttpClientReset(HttpClient ** p)
{
    HttpClientFree(*p);
    (*p) = NewSSLClient();
}

#define CURL_VERBOSE 0



void HttpClientPerform(HttpClient * const c)
{
    curl_easy_setopt(c->handle, CURLOPT_HTTPHEADER, NULL);
    curl_easy_setopt(c->handle, CURLOPT_HTTPHEADER, c->headers);
    #if CURL_VERBOSE
        curl_easy_setopt(c->handle, CURLOPT_VERBOSE, 1L); 
    #endif

    c->last_error = curl_easy_perform(c->handle);
}


boolean HttpClientHasError(const HttpClient * c)
{
    return (c->last_error != CURLE_OK);
}

HttpClient * HttpClientSetDataSent(HttpClient * c, char * data, size_t dat_size, boolean use_put) 
{
    (void)use_put;
    curl_easy_setopt(c->handle, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(c->handle, CURLOPT_POSTFIELDSIZE, dat_size); 
    return c;
}

void HttpClientResetBody(HttpClient * c)
{
    free(c->buf->data);
    c->buf->data = NULL;
    c->buf->size = 0;
}

HttpClient * HttpClientSetOnlyRequestBody(HttpClient * c, char * data, size_t dat_size, boolean put)
{
    curl_easy_setopt(c->handle, put ? CURLOPT_UPLOAD : CURLOPT_HTTPPOST, 1L);
    curl_easy_setopt(c->handle, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(c->handle, CURLOPT_POSTFIELDSIZE, dat_size);
    return c;
}

HttpClient * HttpClientSetUrl(HttpClient * cl, const char * u)
{
    curl_easy_setopt(cl->handle, CURLOPT_URL, u);
    return cl;
}

HttpClient * HttpClientSetMethod(HttpClient * c, const char * m)
{
    curl_easy_setopt(c->handle, CURLOPT_CUSTOMREQUEST, m);
    return c;
}

long HttpClientGetResponseCode(const HttpClient * c)
{
    long value = 0;
    curl_easy_getinfo(c->handle, CURLINFO_RESPONSE_CODE, &value);
    return value;
}

char * HttpClientGetData(HttpClient * c)
{
    return c->buf->data;
}

int InitCurl()
{
    return (int)curl_global_init(CURL_GLOBAL_ALL);
}

void DestroyCurl()
{
    curl_global_cleanup();
}

void HttpClientSetHeadMethod(HttpClient * client)
{
    curl_easy_setopt(client->handle, CURLOPT_NOBODY, 1L);
}