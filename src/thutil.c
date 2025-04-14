#include "thutil.h"

int ThreadDetach(void * thread)
{
    return (thrd_detach(*((thrd_t*)thread)));
}

boolean CreateNewThread(proc_t func, void* arg)
{
    thrd_t thread;

    if (thrd_create(&thread, func, arg) != thrd_success) return false;

    if (ThreadDetach(&thread) != thrd_success) return false;

    return true;
}

void ThreadSleepSeconds(uint32_t seconds)
{
    thrd_sleep(&(struct timespec){.tv_sec = seconds}, NULL);
}

void ThreadSleepMilliseconds(uint32_t millis)
{
    thrd_sleep(&(struct timespec){.tv_nsec=millis * NANOS_IN_MILLIS}, NULL);
}