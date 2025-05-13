#include "file_util.h"
#include "win_misc.h"

int main(int argc, char**argv)
{
    CState console = {0};

    if (CreateNewConsole(&console)) {
        while (true)
        {
            wchar_t     buffer[500];
            wchar_t * lf = NULL;
            fbuf_ptr    outbuf = NULL;
            printf("<< in: ");
            fgetws(buffer, 500, stdin);
            lf = wcschr(buffer, L'\n');

            if (lf) {
                *lf = L'\0';
            }

            if (!wcscmp(buffer, L"exit")) {
                break;
            }

            outbuf = ExecuteCommandInConsole(&console, buffer);
            printf(">> STDOUT size: %d\n", outbuf->bytes);
            fbuf_free(outbuf);
        }
        CloseConsole(&console);
    }

    return 0;
}