#ifndef STRINGH
#define STRINGH

#include "types.h"
#include "encoding.h"
#include <wchar.h>

#define DEFAULT_CAP 12

typedef struct __char
{
    byte * data;
    tiny_t len;
    tiny_t len_encoded;

} character_t, *pcharacter;

typedef struct __str
{
    pcharacter data;
    len_t CurrentSize;
    len_t Capacity;
    Encoding currentEncoding;

} string_t, * pstring_t; // utf-8 string

// creates UTF-8 character from source of byte
pcharacter CreateChar(byte *, Encoding);

// creates UTF-8 string from source of bytes
pstring_t CreateString(const byte *, len_t, Encoding);

pstring_t CreateStringFromWideChars(const wchar_t *, len_t);


// creates UTF-8 character from wide char
pcharacter CreateFromWideChar(const wchar_t);



pstring_t CreateEmptyString();

pstring_t CreateStringCopyOf(pstring_t copyable);

void StringAppend(pstring_t *,const pstring_t);

void StringAppendWideChars(pstring_t,const wchar_t *, len_t);

void StringAppendChars(pstring_t*,const byte*, len_t);

// creates UTF-8 string from raw character bytes
pstring_t CreateFromRawBytes(const char*);

void char_copy(pcharacter from, pcharacter to);

void string_copy(pstring_t * from, pstring_t * to);

wchar_t * GetWideCharsBufferOfString(pstring_t);

byte * GetRawBytes(pstring_t, len_t *);

len_t PrintString(pstring_t str);

byte* GetNullTerminatedBytes(pstring_t str);

boolean StringEquals(pstring_t first, pstring_t second);
void StringDestroy(pstring_t value);

char * StringFmt(const char * fmt, ...);

len_t BytesLen(const char*);


#define CallFunc(name, ...) name(__VA_ARGS__)

#endif