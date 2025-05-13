#include "resource_monitor.h"
#include "resources_def.h"
#include <time.h>
#include <cJSON.h>
#include <windows.h>

// Вспомогательная функция для вычисления процента использования CPU
static integer_t calculate_cpu_usage(len_t prev_total, len_t prev_idle, len_t curr_total, len_t curr_idle) {
    len_t total_diff = curr_total - prev_total;
    len_t idle_diff = curr_idle - prev_idle;

    if (total_diff == ZERO) return ZERO;
    return (integer_t)(((total_diff - idle_diff) * 100) / total_diff);
}

// Сбор данных об использовании CPU
boolean collect_cpu_usage(struct cpu_usage * cpu) {
    if (cpu == nil) return false;

    FILETIME idle_time, kernel_time, user_time;
    if (!GetSystemTimes(&idle_time, &kernel_time, &user_time)) {
        return false;
    }

    // Преобразуем FILETIME в len_t (64-битное значение)
    cpu->idle_time = ((len_t)idle_time.dwHighDateTime << 32) | idle_time.dwLowDateTime;
    cpu->total_time = (((len_t)kernel_time.dwHighDateTime << 32) | kernel_time.dwLowDateTime) +
                      (((len_t)user_time.dwHighDateTime << 32) | user_time.dwLowDateTime);

    // Для точного расчета процента нужно сравнивать с предыдущими значениями
    // Здесь мы просто инициализируем структуру, процент будет вычисляться позже
    cpu->usage_percent = ZERO;
    return true;
}

// Сбор данных об использовании памяти
boolean collect_memory_usage(memory_usage_t* memory) {
    if (memory == nil) return false;

    MEMORYSTATUSEX mem_info;
    mem_info.dwLength = sizeof(MEMORYSTATUSEX);

    if (!GlobalMemoryStatusEx(&mem_info)) {
        return false;
    }

    memory->total_physical = mem_info.ullTotalPhys;
    memory->free_physical = mem_info.ullAvailPhys;
    memory->used_physical = memory->total_physical - memory->free_physical;
    memory->usage_percent = (integer_t)((memory->used_physical * 100) / memory->total_physical);

    return true;
}

// Сбор всех данных мониторинга ресурсов
boolean collect_resource_stats(resource_stats_t* stats) {
    if (stats == nil) return false;

    // Сбор данных CPU
    static cpu_usage_t prev_cpu = {0};
    cpu_usage_t curr_cpu;

    if (!collect_cpu_usage(&curr_cpu)) {
        return false;
    }

    if (prev_cpu.total_time != ZERO) {
        curr_cpu.usage_percent = calculate_cpu_usage(prev_cpu.total_time, prev_cpu.idle_time,
                                                     curr_cpu.total_time, curr_cpu.idle_time);
    }
    stats->cpu = curr_cpu;
    prev_cpu = curr_cpu; // Сохраняем текущие значения для следующего вызова

    // Сбор данных памяти
    if (!collect_memory_usage(&stats->memory)) {
        return false;
    }

    // Установка временной метки
    stats->timestamp = (unix_time_t)time(nil);

    return true;
}

byte * resource_stats_to_json(const resource_stats_t* stats) 
{
    if (stats == nil) {
        return NULL;
    }

    // Создаем корневой объект JSON
    cJSON* root = cJSON_CreateObject();
    if (root == NULL) {
        return NULL;
    }

    // Добавляем поле timestamp
    cJSON_AddNumberToObject(root, "timestamp", (double)stats->timestamp);

    // Создаем объект для CPU
    cJSON* cpu = cJSON_CreateObject();
    if (cpu == NULL) {
        cJSON_Delete(root);
        return NULL;
    }
    cJSON_AddNumberToObject(cpu, "total_time", (double)stats->cpu.total_time);
    cJSON_AddNumberToObject(cpu, "idle_time", (double)stats->cpu.idle_time);
    cJSON_AddNumberToObject(cpu, "usage_percent", stats->cpu.usage_percent);
    cJSON_AddItemToObject(root, "cpu", cpu);

    // Создаем объект для Memory
    cJSON* memory = cJSON_CreateObject();
    if (memory == NULL) {
        cJSON_Delete(root);
        return NULL;
    }
    cJSON_AddNumberToObject(memory, "total_physical", (double)stats->memory.total_physical);
    cJSON_AddNumberToObject(memory, "used_physical", (double)stats->memory.used_physical);
    cJSON_AddNumberToObject(memory, "free_physical", (double)stats->memory.free_physical);
    cJSON_AddNumberToObject(memory, "usage_percent", stats->memory.usage_percent);
    cJSON_AddItemToObject(root, "memory", memory);

    // Преобразуем объект в строку
    byte * json_str = cJSON_Print(root);
    
    // Освобождаем память, выделенную для объекта cJSON
    cJSON_Delete(root);

    return json_str;
}