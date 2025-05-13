#include "OSInfo.h"
#include <stdio.h>
#include <stdlib.h>
#include "resources_def.h"

int main()
{
    int err = -1;
    char * info;
    POSInfo p;
    
    p = GetLatestOsInfo();
        if (p) {
            err = 0;
        }
        

        info = OSInfoToJson(p);
        if (info) {
            printf("info: %s\n", info);
            free(info);
        }
        OSInfoFree(&p);

    return err;
}