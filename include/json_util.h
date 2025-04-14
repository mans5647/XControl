



#define json_declare_serialize_callback(T, str) \
    typedef str (*T##ToJsonCallbackT)(struct T *)

#define json_declare_deserialize_callback(T, str) \
    typedef struct T* (* T##FromJsonCallbackT)(str)

#define json_declare_fn_to_json(T, str) \
    str T##ToJson(const T *)

#define json_fn_begin(T, str) \
    str T##ToJson(const T * data) {
#define json_fn_end() }

#define arr_to_json(T, count_t, str) \
    str T##ToJson(const T* data, count_t size)

#define arr_to_json_begin(T, c, str) arr_to_json(T, c, str) {
#define arr_to_json_end() }


#define json_declare_fn_from_json(T, str)\
    T * fromJson(str)

#define json_define_callback_type_to(T, str)\
    str (*ToJson)(const struct T *)

#define json_define_callback_type_from(T, str)\
    struct T * (*FromJson)(str)