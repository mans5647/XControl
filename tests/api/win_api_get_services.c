#include "OSInfo.h"
#include <stdio.h>


int main()
{
    int err;
    services_t services;
    err = GetAllWindowsServices(&services);
    return err;
}