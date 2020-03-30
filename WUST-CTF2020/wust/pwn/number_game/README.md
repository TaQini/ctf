## number_game

- 题目描述：

  > Author: ColdShield
  >
  > hint: NEG

- 题目附件：[number_game](https://cdn.jsdelivr.net/gh/TaQini/CTFq@master/)

- 考察点：整数范围

- 难度：简单

- 初始分值：1000

- 最终分值：919

- 完成人数：16

### 程序分析

程序关键部分如下：

``` c
__isoc99_scanf("%d", &v1);
if ( v1 < 0 ){
    v1 = -v1;
    if ( v1 < 0 )
        shell();
    else
        printf("You lose");
}
```

读一个整数，如果小于0就取反，如果还小于0就给shell

### 解题思路

这题和[ACTF2020](http://taqini.space/2020/02/13/ACTF2020-writeup/#Pwn)考察abs函数那题原理相同

> `abs(-2147483648)`的返回值仍然是个负数

所以直接输入`-2147483648`即可然过两次判断

