#ifndef TYPES
#define TYPES


#define nil (void*)0

typedef int                             integer_t;
typedef short                           tiny_t;
typedef unsigned int                    len_small_t;
typedef unsigned long long              len_t;
typedef char                            byte;
typedef char                            bool_;
typedef long long                       very_long_t;
typedef unsigned short                  ushort_t;

typedef const byte*                     byte_literal_t;
typedef byte*                           byte_ptr_t;
typedef long long                       unix_time_t;

typedef bool_ boolean;

#define true 1
#define false 0
#define ZERO 0
#define AsObject(to, value) (to*)(&value)
#define GetAttributeOf(value, attr) value->attr


#endif