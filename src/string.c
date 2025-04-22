#define WIN32_LEAN_AND_MEAN

#include "my_string.h"
#include "encoding.h"
#include "util.h"
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#define ASCII_VALUE_LEN     1
#define ASCII_MIN_BYTES_LEN 2
#define ONE_CHAR            1

static inline tiny_t CountBytes(byte ch)
{
    if (ch <= 0x7F) return 1;
    if ((ch & 0xE0) == 0xC0) return 2;
    if ((ch & 0xF0) == 0xE0) return 3;
    if ((ch & 0xF8) == 0xF0) return 4;
	return -1;
}

static boolean ResizeUnit(pcharacter block, const tiny_t newsize)
{
    if (block->len >= newsize) return false;
    block->data = DataReallocCount(byte, newsize, block->data);
    if (!block->data) return false;
    block->len = newsize;
    return true;
}

void char_copy(pcharacter src, pcharacter dest)
{
    byte * src_bytes = src->data;
    byte * dst_bytes = dest->data;

    tiny_t toCopy = src->len;
    for (ushort_t i = 0; i < toCopy; i++)
    {
        dst_bytes[i] = src_bytes[i];
    }

}

void copyArr(const byte * src, byte * dst, int len)
{
    while (len)
    {
        (*dst++) = (*src++);
        len--;
    }
}

void copyCharacter(pcharacter src, pcharacter dst)
{

    for (len_t i = 0; i < src->len; i++)
    {
        dst->data[i] = src->data[i];
    }

    dst->len = src->len;
    dst->len_encoded = src->len_encoded;
}



pcharacter CreateChar(byte* origin, Encoding desiredEnc)
{
    (void)desiredEnc;
    pcharacter newchar = NewMemory(character_t, sizeof(character_t));
    
    newchar->data = NULL;
    newchar->len = 0;
    newchar->len_encoded = 0;


    int16_t bytes = CountBytes(*origin);
    if (bytes != -1)
    {
        const int16_t bytes_cap = bytes + 1;
        newchar->data = NewMemory(byte, bytes_cap);
        
        for (integer_t i = 0; i < bytes; i++)
        {
            newchar->data[i] = (*origin);
            origin++;
        }
        
        newchar->len_encoded = bytes;
        newchar->len = bytes_cap;
        newchar->data[bytes] = '\0';
    }

    return newchar;
}

pstring_t CreateString(const byte * origin, len_t len, Encoding encoding)
{
    if (encoding == UTF_8) {
        pstring_t nStr = NewMemory(string_t, sizeof(string_t));
        nStr->Capacity = DEFAULT_CAP;
        
        if (len >= DEFAULT_CAP)
        {
            nStr->Capacity = (len * 2);
        }

        nStr->data = NewMemory(character_t, sizeof(character_t) * nStr->Capacity);

        nStr->CurrentSize = 0;
        const byte *ptr = origin;

        for (len_t i = 0; i < len && *ptr;)
        {
            tiny_t bytes = CountBytes(*ptr);
            if (bytes <= 0 || bytes > len - i) break;
            pcharacter ch = &nStr->data[nStr->CurrentSize++];
            ch->len_encoded = bytes;
            ch->len = bytes + 1;
            ch->data = NewMemory(byte, ch->len);
            if (!ch->data) {
                StringDestroy(nStr);
                return NULL;
            }
            copyArr(ptr, ch->data, bytes);
            ch->data[bytes] = '\0';
            ptr += bytes;
            i += bytes;
        }

        nStr->currentEncoding = UTF_8;
        return nStr;

    } else if (encoding == US_ASCII) {

        pstring_t nStr = NewMemory(string_t, sizeof(string_t));
        nStr->Capacity = DEFAULT_CAP;
        
        if (len > DEFAULT_CAP)
        {
            nStr->Capacity = len;
        }

        nStr->data = AllocCount(character_t, nStr->Capacity);
        nStr->CurrentSize = 0;

        pcharacter myCharNext = nStr->data;

        for (len_t i = 0; i < len; i++) {
            myCharNext->data = NewMemory(byte, ASCII_MIN_BYTES_LEN);
            myCharNext->len = ASCII_VALUE_LEN;
            myCharNext->len_encoded = ASCII_VALUE_LEN;
            copyArr(&origin[i],myCharNext->data, ASCII_VALUE_LEN);
            nStr->CurrentSize++;
            myCharNext++;
        }

        nStr->currentEncoding = US_ASCII;
        return nStr;
    }

    return NULL;
}

pstring_t CreateEmptyString()
{
    pstring_t str = NewMemory(string_t, sizeof(string_t));
    str->Capacity = 0;
    str->CurrentSize = 0;
    str->data = NULL;
    return str;
}

pstring_t CreateStringCopyOf(pstring_t copyable)
{
    if (!copyable) return NULL;
    pstring_t copy = NewMemory(string_t, sizeof(string_t));
    if (!copy) return NULL;
    copy->Capacity = copyable->Capacity;
    copy->CurrentSize = copyable->CurrentSize;
    copy->data = NewMemory(character_t, copyable->Capacity * sizeof(character_t));
    if (!copy->data) {
        free(copy);
        return NULL;
    }
    for (len_t i = 0; i < copyable->CurrentSize; i++) {
        pcharacter cpCharTo = &copy->data[i];
        pcharacter cpCharFrom = &copyable->data[i];
        cpCharTo->len = cpCharFrom->len;
        cpCharTo->len_encoded = cpCharFrom->len_encoded;
        cpCharTo->data = NewMemory(byte, cpCharFrom->len);
        if (!cpCharTo->data) {
            StringDestroy(copy);
            return NULL;
        }
        copyArr(cpCharFrom->data, cpCharTo->data, cpCharFrom->len);
    }
    return copy;
}

pcharacter CreateFromWideChar(const wchar_t ch)
{
    pcharacter newchar = NewMemory(character_t, sizeof(character_t));
    
    newchar->len = 0;
    newchar->len_encoded = 0;
    newchar->data = NULL;

    integer_t bytes = 0, totalAlloc = 0;
    
    bytes = (ch <= SCHAR_MAX) ? 1 : 2;
    
    totalAlloc = bytes + 1;
    
    byte * data = NewMemory(byte, totalAlloc);
    int szBytes = WideCharToMultiByte(CP_UTF8, 0, &ch, 1, data, totalAlloc, NULL, NULL);
    if (szBytes == 0)
    {
        free(data);
        return newchar;
    }

    data[szBytes] = '\0';
    newchar->data = data;
    newchar->len = (tiny_t)totalAlloc;
    newchar->len_encoded = (tiny_t)szBytes;
    return newchar;
}

void CreateWideCharInplace(pcharacter ch_, const wchar_t ch)
{
    ch_->data = NULL;
    ch_->len = 0;
    ch_->len_encoded = 0;

    integer_t bytes = 0, totalAlloc = 0;
    
    bytes = (ch <= SCHAR_MAX) ? 1 : 2;
    
    totalAlloc = bytes + 1;
    
    byte * data = NewMemory(byte, totalAlloc);
    int szBytes = WideCharToMultiByte(CP_UTF8, 0, &ch, 1, data, totalAlloc, NULL, NULL);
    if (szBytes == 0)
    {
        free(data);
        return;
    }

    data[szBytes] = '\0';
    ch_->data = data;
    ch_->len = (tiny_t)totalAlloc;
    ch_->len_encoded = (tiny_t)szBytes;
}

pstring_t CreateStringFromWideChars(const wchar_t * data, len_t size)
{
    if (size == 0) return NULL;

    pstring_t str = (pstring_t)malloc(sizeof(string_t));
    
    str->Capacity = 0;
    str->CurrentSize = 0;
    str->data = NULL;
    str->currentEncoding = UTF_8;

    len_t bytes_alloc = size * 2;

    str->data = AllocCount(character_t, bytes_alloc);

    if (!str->data)
    {
        StringDestroy(str);
        return NULL;
    }

    for (size_t k = 0; k < size; k++)
    {
        CreateWideCharInplace(&str->data[k], data[k]);
        str->CurrentSize += 1;
    }

    str->Capacity = bytes_alloc;

    return str;
}

len_t CalcNewCapacity(len_t old_capacity, len_t new_size)
{
    return old_capacity + (new_size - old_capacity) * 2;
}

void StringAppend(pstring_t * dst, const pstring_t str)
{
    const len_t OldSize = (*dst)->CurrentSize;

    if (!OldSize) {
        (*dst) = CreateStringCopyOf(str);
        return;
    }
    const len_t DesiredLenNewStr = OldSize + str->CurrentSize;
    const len_t OldCapacity = (*dst)->Capacity;
    
    if (DesiredLenNewStr >= OldCapacity)
    {
        len_t NewCap = CalcNewCapacity(OldCapacity, DesiredLenNewStr);
        pcharacter data = DataRealloc(character_t, sizeof(character_t) * NewCap, (*dst)->data);
        (*dst)->Capacity = NewCap;
        (*dst)->data = data;
    }
    

    len_t AppendPos = (*dst)->CurrentSize;
    
    pcharacter out_char = &(*dst)->data[AppendPos];
    pcharacter in_char = str->data;
    
    len_t _cnt = str->CurrentSize;
    while (_cnt != 0)
    {
        out_char->data = NewMemory(byte, sizeof(byte) * in_char->len);
        copyCharacter(in_char, out_char);
        out_char++;
        in_char++;
        
        _cnt--;
    }
    
    (*dst)->CurrentSize += str->CurrentSize;
}

void StringAppendWideChars(pstring_t out, const wchar_t * str, len_t size)
{
    pstring_t newStr = CreateStringFromWideChars(str, size);
    StringAppend(&out, newStr);
    StringDestroy(newStr);
}

void StringAppendChars(pstring_t * out, const byte* str, len_t sz)
{ 
    pstring_t s = CreateString(str, sz, US_ASCII);
    StringAppend(out, s);
    StringDestroy(s); 
}

void StringAppendWideNullTerm(pstring_t out, const wchar_t * str)
{
    len_t size = wcslen(str);
    StringAppendWideChars(out, str, size);
}

boolean IsStringValid(pstring_t * b)
{
    if ((*b) == NULL) return false;
    return ((*b)->data != NULL && (*b)->CurrentSize >= ONE_CHAR);
}

static byte * GetRawBytesFromString(pcharacter _ch, len_t sizeBytes, len_t sizeChars, len_t * copied)
{
    byte * buffer = NewMemory(byte, sizeBytes);
    byte * bufPos = buffer;
    len_t bCopied = 0;
    while (sizeChars != 0) 
    {
        copyArr(_ch->data, bufPos, _ch->len_encoded);
        bufPos += _ch->len_encoded;
        bCopied += _ch->len_encoded;
        _ch++;
        sizeChars--;
    }
    
    (*copied) = bCopied;
    return buffer;
}

byte * GetRawBytes(pstring_t str, size_t * count)
{
    size_t cBytes = 0;
    pcharacter _dataSingleChar = str->data;
    for (int i = 0; i < str->CurrentSize; i++) 
    {
        cBytes += _dataSingleChar->len_encoded;
        _dataSingleChar++;
    }
 
    size_t LenBytesTotalAlloc = cBytes + 1;
 
    len_t copied = 0;
    
    byte * rawChars = GetRawBytesFromString(str->data, LenBytesTotalAlloc, str->CurrentSize, &copied);
    
    (*count) = copied;
    
    return rawChars;
}

byte* GetNullTerminatedBytes(pstring_t str)
{
    if (!str) return NULL;
    size_t count = 0;
    byte * buffer = GetRawBytes(str, &count);
    buffer[count] = '\0';
    return buffer;
}

wchar_t * GetWideCharsBufferOfString(pstring_t str)
{
    int cBytes = 0;
    pcharacter _dataSingleChar = str->data;
    for (len_t i = 0; i < str->CurrentSize; i++) {

        cBytes += _dataSingleChar->len_encoded;
        _dataSingleChar++;
    }

    int LenBytesTotalAlloc = cBytes + 1;
 
    len_t copied = 0;

    byte * rawChars = GetRawBytesFromString(str->data, LenBytesTotalAlloc, str->CurrentSize, &copied);
    
    int32_t size = (int32_t)(copied * sizeof(wchar_t));
    wchar_t * buf = NewMemory(wchar_t, size);

    (void)MultiByteToWideChar(CP_UTF8, 0, rawChars, -1, buf, size);

    return buf;
}


len_t PrintString(pstring_t str)
{
    if (!str || str->CurrentSize == 0) return 0;
    pcharacter _ptr = str->data;
    for (len_t i = 0; i < str->CurrentSize; i++) {
        printf("%.*s", _ptr->len_encoded, _ptr->data);
        _ptr++;
    }
    return str->CurrentSize;

}

len_t BytesLen(const char* ptr)
{
    const char * end = ptr;
    while ((*++end));

    return (end - ptr);
}

boolean StringEquals(pstring_t first, pstring_t second)
{
    if (first->CurrentSize > second->CurrentSize) return false;
    else if (second->CurrentSize > first->CurrentSize) return false;
    else {

        pcharacter ch_ptr_one = first->data;
        pcharacter ch_ptr_two = second->data;
        for (len_t i = 0; i < first->CurrentSize; i++) {
            
            assert(ch_ptr_one->len_encoded == ch_ptr_two->len_encoded);

            if (memcmp(ch_ptr_one->data, ch_ptr_two->data, ch_ptr_one->len_encoded)) return false;

            ch_ptr_one++;
            ch_ptr_two++;

        }
    }

    return true;
}

void CharacterDestroy(pcharacter ch)
{
    free(ch->data);
}

void StringDestroy(pstring_t value)
{
    if (value == NULL) return;
    
    pcharacter ch = value->data;

    for (int i = 0; i < value->CurrentSize; i++)
    {
        CharacterDestroy(ch);
        ch++;
    }

    free(value->data);
    free(value);
}

void string_copy(pstring_t * from, pstring_t * to)
{
    pstring_t src = (*from);
    pstring_t dst = (*to);

    dst->Capacity = src->Capacity;
    dst->currentEncoding = src->currentEncoding;
    dst->CurrentSize = src->CurrentSize;
    
    pcharacter pCharSrc = src->data;
    pcharacter pCharDst = dst->data;

    len_t CopyChars = src->CurrentSize;
    
    while (CopyChars)
    {
        char_copy(pCharSrc, pCharDst);
        pCharSrc++;
        pCharDst++;
        CopyChars--;
    }

}

#include "file_util.h"

void _put_buf(char value, void * buffer, const size_t index, const size_t max_len) {

    if (index < max_len) {
        ((char*)buffer)[index] = value;
    }
    
}

#define CHUNK_SIZE 20

void append_or_realloc(fbuf_ptr buf, char byte) {

    if (buf->data == NULL) {
        buf->capacity += CHUNK_SIZE;
        buf->data = realloc(NULL, buf->capacity + 1);
    }

    else if (buf->bytes >= buf->capacity) {
        buf->capacity += CHUNK_SIZE;
        buf->data = realloc(buf->data, buf->capacity + 1);
    }

    buf->data[buf->bytes] = byte;
    buf->bytes++;
}

size_t _size_t_reverse(size_t value)
{
    size_t nvalue = 0;
    while (value)
    {
        char digit = (value % 10);
        nvalue = (nvalue * 10) + digit;
        value /= 10;
    }

    if (value > ULLONG_MAX) return 0;

    return nvalue;
}

int _int_reverse(int value)
{
    int nvalue = 0;
    while (value)
    {
        char digit = (value % 10);
        nvalue = (nvalue * 10) + digit;
        value /= 10;
    }

    if (value < INT_MIN || value > INT_MAX) return 0;

    return nvalue;
}

void _size_t_2_bytes_apnd(const size_t * value, fbuf_ptr buf) {

    size_t copy = _size_t_reverse(*value);

    do {
        char digit = (char)(copy % 10);
        digit = digit < 10 ? '0' + digit : digit - 10;
        append_or_realloc(buf, digit);
        copy /= 10;
    } while (copy);

}

void _int_to_bytes_apnd(const int * value, fbuf_ptr buf)
{
    int copy = _int_reverse(*value);
    do {
        char digit = (char)(copy % 10);
        digit = digit < 10 ? '0' + digit : digit - 10;
        append_or_realloc(buf, digit);
        copy /= 10;
    } while (copy);   
}
 


char * StringFmt(const char * fmt, ...)
{
    fbuf_t buf;
    va_list va;

    fbuf_init(&buf);
    va_start(va, fmt);

    while (*fmt)
    {
        if (*fmt != '%') 
        {
            append_or_realloc(&buf, *fmt);
            fmt++;
            continue;
        } else {
            fmt++;
        }

        switch (*fmt)
        {
            case 'u':
            {
                if (*(fmt + 1) == 's') {
                    const pstring_t _ustr = va_arg(va, pstring_t);
                    char * _dat = GetNullTerminatedBytes(_ustr);
                    size_t _len = strlen(_dat);
                    
                    while (_len)
                    {
                        append_or_realloc(&buf, (*_dat));
                        _dat++;
                        _len--;
                    }

                    free(_dat);
                    fmt += 2;
                }

                break;

            } case 's': {
                const char * _dat = va_arg(va, const char*);
                size_t _len = strlen(_dat);

                while (_len)
                {
                    append_or_realloc(&buf, (*_dat));
                    _dat++;
                    _len -= 1;
                }

                fmt += 1;
                break;
                
            } case 'd': {
                size_t off = 1;
                if (*(fmt + 1) == 'z') {
                    const size_t _sz = va_arg(va, size_t);
                    _size_t_2_bytes_apnd(&_sz, &buf);
                    off = 2;
                }

                else if (*(fmt + 1) == 'i') {
                    const int _val_int = va_arg(va, int);
                    _int_to_bytes_apnd(&_val_int, &buf);
                    off = 2;
                }

                fmt += off;

                break;
            }

            default:
                append_or_realloc(&buf, *fmt);
                fmt++;
        }

    }

    va_end(va);
    buf.data[buf.bytes] = '\0';
    return buf.data;
}