#ifndef TH_UTIL
#define TH_UTIL

#include "types.h"
#include <threads.h>
#include <stdint.h>

#define SLEEP_SECONDS_DEFAULT   1
#define SLEEP_SECONDS_MEDIUM    5
#define SLEEP_SECONDS_MAX       SLEEP_SECONDS_MEDIUM * 2
#define SLEEP_MILLIS_DEFAULT    100
#define NANOS_IN_MILLIS         1000000

typedef thrd_start_t proc_t;

boolean     CreateNewThread(proc_t, void*);
void        ThreadSleepSeconds(uint32_t seconds);
void        ThreadSleepMilliseconds(uint32_t millis);
int         ThreadDetach(void *thread);

#endif