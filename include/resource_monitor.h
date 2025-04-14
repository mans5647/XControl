#ifndef RESOURCE_MONITOR_H
#define RESOURCE_MONITOR_H

#include "types.h"


// Структура для хранения данных об использовании CPU
typedef struct {
    len_t total_time;           // Общее время процессора (в тиках)
    len_t idle_time;            // Время простоя процессора (в тиках)
    integer_t usage_percent;    // Процент использования CPU
} cpu_usage_t;

// Структура для хранения данных об использовании памяти
typedef struct {
    len_t total_physical;       // Общий объем физической памяти (в байтах)
    len_t used_physical;        // Используемая физическая память (в байтах)
    len_t free_physical;        // Свободная физическая память (в байтах)
    integer_t usage_percent;    // Процент использования памяти
} memory_usage_t;

// Структура для объединения всех данных мониторинга ресурсов
typedef struct {
    cpu_usage_t cpu;            // Данные об использовании CPU
    memory_usage_t memory;      // Данные об использовании памяти
    unix_time_t timestamp;      // Время сбора данных (в формате UNIX)
} resource_stats_t;

// Функции для сбора данных
boolean collect_cpu_usage(cpu_usage_t* cpu);
boolean collect_memory_usage(memory_usage_t* memory);
boolean collect_resource_stats(resource_stats_t* stats);
byte * resource_stats_to_json(const resource_stats_t* stats);

#endif