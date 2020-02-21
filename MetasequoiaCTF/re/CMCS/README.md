## CMCS

- 题目描述：

  > 你主导开发的CMCS(`Cyber Malware Control Software`)可以对全球各个角落的网络爬虫进行监控。但是今天，它似乎失灵了…… 
  >
  > **得到的flag请包上flag提交。** 
  >
  > By *?*

 - 题目附件：[attachment.zip](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Reverse/CMCS/attachment.zip)

 - 考察点：逆向分析

 - 难度：简单

 - 初始分值：100

 - 最终分值：91

 - 完成人数：5

主要代码：

```c
void sub_8048708(){
  wchar_t ws[8192]; // [esp+1Ch] [ebp-800Ch]
  wchar_t *s2; // [esp+801Ch] [ebp-Ch]

  s2 = sub_8048658(&s, &dword_8048A90);
  if ( fgetws(ws, 0x2000, stdin) ){
    ws[wcslen(ws) - 1] = 0;
    if ( !wcscmp(ws, s2) )
      wprintf(&right);
    else
      wprintf(&failed);
  }
  free(s2);
}
```

输入的字符串与`sub_8048658`的返回结果做比较，直接`gdb`调试，获取`sub_8048658`的返回值即为flag

> 9447{you_are_an_international_mystery}

9447 CTF 原题，flag都没改...