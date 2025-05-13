#ifndef RESOURCE_MONITOR_H
#define RESOURCE_MONITOR_H

#include "types.h"
#include "resources_fwd.h"


// Функции для сбора данных
boolean collect_cpu_usage(struct cpu_usage* cpu);
boolean collect_memory_usage(struct memory_usage* memory);
boolean collect_resource_stats(struct resource_stats* stats);
byte * resource_stats_to_json(const struct resource_stats* stats);

#endif