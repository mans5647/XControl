#ifndef FORMATTER
#define FORMATTER
#include <stdint.h>

char * FormatWinError(uint32_t err);

void FreeMessage(void *buf);

#endif