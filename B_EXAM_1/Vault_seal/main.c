#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define SEAL_CONST 0x9e3779b97f4a7c15UL

unsigned long strlen_compat(const char *s);

void win(void) {
    char *f = getenv("FLAG");
    if (f) {
        write(1, f, strlen_compat(f));
        write(1, "\n", 1);
    } else {
        write(1, "no flag set\n", 12);
    }
    fflush(stdout);
    _exit(0);
}

unsigned long strlen_compat(const char *s) {
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}

void vuln(void) {
    unsigned long seal = SEAL_CONST;
    char note[64];

    write(1, "Engrave your note on the seal: ", 31);

    read(0, note, 104);

    if (seal != SEAL_CONST) {
        write(2, "ALARM\n", 6);
        _exit(1);
    }

    return;
}

int main(void) {
    write(1, "== The Vault Seal ==\n", 21);
    vuln();
    return 0;
}
