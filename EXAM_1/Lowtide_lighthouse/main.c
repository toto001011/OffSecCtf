#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void win(void);

void banner(void)
{
    char tag[24];

    write(1, "=== Lowtide Lighthouse Lamp Control ===\n", 40);
    write(1, "Pattern code (tag): ", 20);

    read(0, tag, 25);

    write(1, "Registered pattern: ", 20);
    write(1, tag, 32);
    write(1, "\n", 1);
}

void log_entry(void)
{
    char line[16];

    write(1, "Keeper's log (one line): ", 25);

    read(0, line, 41);
    write(1, "Log saved.\n", 11);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    banner();
    log_entry();

    write(1, "Goodnight, keeper.\n", 19);
    return 0;
}

void win(void)
{
    const char *flag = getenv("FLAG");
    if (flag) {
        write(1, "\n[lamp] keeper override accepted:\n", 34);
        write(1, flag, strlen(flag));
        write(1, "\n", 1);
    } else {
        write(1, "\n[lamp] FLAG not set in environment\n", 36);
    }
    fflush(stdout);
    _exit(0);
}
