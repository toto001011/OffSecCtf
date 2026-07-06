#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>

struct Lantern {
    char name[24];
    void (*flash)(struct Lantern *self);
};

_Static_assert(offsetof(struct Lantern, flash) >= 16,
               "flash must sit past the tcache fd+key (>= offset 16)");
_Static_assert(sizeof(struct Lantern) == 32,
               "struct Lantern must be a 0x30 tcache chunk");

static struct Lantern *reg = NULL;

static void setup(void) {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void default_flash(struct Lantern *self) {
    (void)self;
    write(1, "[lantern] the brass relay blinks: . . .\n", 40);
}

__attribute__((used, aligned(0x1000), section(".text.winpage")))
static void win_pagegap(void) {

    __asm__ __volatile__(".skip 0x10000, 0x90\n");
}

__attribute__((aligned(0x1000), section(".text.win")))
void win(struct Lantern *self) {
    (void)self;
    char *f = getenv("FLAG");
    if (f) {
        write(1, "[harbor] override relay engaged:\n", 33);
        write(1, f, strlen(f));
        write(1, "\n", 1);
    } else {
        write(1, "no flag\n", 8);
    }
    fflush(stdout);
    _exit(0);
}

static int read_choice(void) {
    char line[32] = {0};
    if (!fgets(line, sizeof(line), stdin)) _exit(0);
    return atoi(line);
}

static void commission(void) {
    if (reg) {

        puts("[-] A lantern is already on the desk. Scrap it first.");
        return;
    }
    reg = malloc(sizeof(struct Lantern));
    if (!reg) _exit(1);
    reg->flash = default_flash;
    printf("Name the lantern: ");

    read(STDIN_FILENO, reg->name, sizeof(reg->name));
    puts("[+] Lantern commissioned.");
}

static void scrap(void) {
    if (!reg) {
        puts("[-] No lantern on the desk.");
        return;
    }
    free(reg);
    puts("[+] Lantern scrapped.");
}

static void inspect(void) {
    if (!reg) {
        puts("[-] No lantern on the desk.");
        return;
    }

    write(1, "Record: ", 8);
    write(1, reg, sizeof(struct Lantern));
    write(1, "\n", 1);
}

static void reforge(void) {

    struct Lantern *scratch = malloc(sizeof(struct Lantern));
    if (!scratch) _exit(1);
    printf("Reforge bytes: ");

    read(STDIN_FILENO, scratch, sizeof(struct Lantern));
    puts("[+] Lantern reforged.");
}

static void signal_lantern(void) {
    if (!reg) {
        puts("[-] No lantern on the desk.");
        return;
    }
    reg->flash(reg);
}

int main(void) {
    setup();

    puts("== Harbor Lantern Registry ==");

    while (1) {
        puts("");
        puts("1. Commission lantern");
        puts("2. Scrap lantern");
        puts("3. Inspect lantern");
        puts("4. Reforge lantern");
        puts("5. Signal lantern");
        puts("6. Leave the harbor");
        printf("> ");

        switch (read_choice()) {
        case 1: commission();      break;
        case 2: scrap();           break;
        case 3: inspect();         break;
        case 4: reforge();         break;
        case 5: signal_lantern();  break;
        case 6: return 0;
        default: puts("[-] Unknown command.");
        }
    }
}
