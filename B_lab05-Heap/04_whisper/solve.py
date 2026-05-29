#!/usr/bin/env python3
from pwn import *
import os

context.binary = elf = ELF('./whisper', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

def conn():
    if args.REMOTE:
        return remote('localhost', 1337)
    return process(elf.path)

p = conn()

p.interactive()
