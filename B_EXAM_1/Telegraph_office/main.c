#include <unistd.h>
#include <string.h>
#include <stdio.h>

static void out(const char *s)
{
    write(1, s, strlen(s));
}

void send_message(void)
{
    char msg[200];
    char ack[8];

    memset(msg, 0, sizeof(msg));
    memset(ack, 0, sizeof(ack));

    out("OPERATOR> Tap your message on the key:\n");

    long n = read(0, msg, 0x120); // --> 288 read  possibile BOF

    out("LINE> ");
    if (n > 0)
        write(1, msg, (size_t)n);

    out("OPERATOR> Message relayed.\n");
}

int main(void)
{
    setvbuf(stdin, 0, 2 , 0);
    setvbuf(stdout, 0, 2 , 0);

    out("=== The Telegraph Office ===\n");
    out("A vintage relay, humming on the wire.\n\n");

    for (int i = 0; i < 3; i++)
        send_message();

    out("OPERATOR> Closing the line. 73.\n");
    return 0;
}
