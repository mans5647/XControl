#ifndef FWD_RDEF
#define FWD_RDEF

#include "types.h"
#include "resources_fwd.h"
// Структура для хранения данных об использовании CPU
typedef struct cpu_usage {
    len_t total_time;           // Общее время процессора (в тиках)
    len_t idle_time;            // Время простоя процессора (в тиках)
    integer_t usage_percent;    // Процент использования CPU
} cpu_usage_t;

// Структура для хранения данных об использовании памяти
typedef struct memory_usage {
    len_t total_physical;       // Общий объем физической памяти (в байтах)
    len_t used_physical;        // Используемая физическая память (в байтах)
    len_t free_physical;        // Свободная физическая память (в байтах)
    integer_t usage_percent;    // Процент использования памяти
} memory_usage_t;

// Структура для объединения всех данных мониторинга ресурсов
typedef struct resource_stats {
    cpu_usage_t cpu;            // Данные об использовании CPU
    memory_usage_t memory;      // Данные об использовании памяти
    unix_time_t timestamp;      // Время сбора данных (в формате UNIX)
} resource_stats_t;


#endif