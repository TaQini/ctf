## babysmali

- 题目描述：

  > 你似乎找到了破坏CMCS的软件，于是尝试对其进行逆向，希望能发现这一切背后的始作俑者…… 
  >
  > **得到的 flag 请包上 flag{} 提交。** 
  >
  > By *?*

 - 题目附件：[attachment.zip](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Reverse/Babysmali/attachment.zip)

 - 考察点：smali逆向、base64换表

 - 难度：简单

 - 初始分值：250

 - 最终分值：245

 - 完成人数：2


先把smali转成java，再分析即可，用到的工具如下：

- smali.jar
- dex2jar-2.0
- jd-gui

### smali->dex

```shell
$ java -jar ./smali.jar ass ./src.smali
```

### dex->jar

```shell
$ ./d2j-dex2jar.sh ./out.dex
```

### jar->java

用jd-gui打开jar文件

```java
package com.example.hellosmali.hellosmali;

public class Digest {
  public static boolean check(String paramString) {
    if (paramString != null && paramString.length() != 0) {
      char[] arrayOfChar = paramString.toCharArray();
      StringBuilder stringBuilder2 = new StringBuilder();
      int i;
      for (i = 0; i < arrayOfChar.length; i++) {
        String str1;
        for (str1 = Integer.toBinaryString(arrayOfChar[i]); str1.length() < 8; str1 = "0" + str1);
        stringBuilder2.append(str1);
      } 
      while (stringBuilder2.length() % 6 != 0)
        stringBuilder2.append("0"); 
      String str = String.valueOf(stringBuilder2);
      arrayOfChar = new char[str.length() / 6];
      for (i = 0; i < arrayOfChar.length; i++) {
        int j = Integer.parseInt(str.substring(0, 6), 2);
        str = str.substring(6);
        arrayOfChar[i] = "+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".charAt(j);
      } 
      StringBuilder stringBuilder1 = new StringBuilder(String.valueOf(arrayOfChar));
      if (paramString.length() % 3 == 1) {
        stringBuilder1.append("!?");
      } else if (paramString.length() % 3 == 2) {
        stringBuilder1.append("!");
      } 
      return String.valueOf(stringBuilder1).equals("xsZDluYYreJDyrpDpucZCo!?");
    } 
    return false;
  }
}
```

### 解密

自定义base64，写脚本解密：

```python
#!/usr/bin/python
#__author__:TaQini

table = "+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

res = "xsZDluYYreJDyrpDpucZCo!?"[:-2]

l = []
for i in res:
    l.append(table.index(i))

s = ''
for i in l:
    b = bin(i)[2:].rjust(6,'0')
    s += b

# print s

h = hex(int(s,2))[2:-2]
# print h

print "flag{%s}"%h.decode('hex')
```

