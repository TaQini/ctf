
## Closed
- 题目描述：
  
    > Author: ColdShield
- 题目附件：[closed](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WUST-CTF2020/pwn/closed/closed)
- 考察点：重定向
- 难度：入门
- 初始分值：1000
- 最终分值：971
- 完成人数：10

### 程序分析
```nasm
mov     edi, 1          ; fd
call    _close
mov     edi, 2          ; fd
call    _close
mov     eax, 0
call    shell
```

### 解题思路

考察基础知识，直接`exec 1>&0`把`stdout`重定向到`stdin`就行了。
