```
% binwalk run.exe

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Microsoft executable, portable (PE)
76464         0x12AB0         TIFF image data, little-endian offset of first image directory: 8
362760        0x58908         XML document, version: "1.0"
```

分离出三个文件.exe .tif .xml，exe中找tif，发现`0x411c30`处的字符串`njCp1HJBPLVTxcMhUHDPwE7mPW`

![](http://image.taqini.space/img/20200624144624.png)



tif文件用ps打开，去掉矩形图层，可以得到加密的代码

![](http://image.taqini.space/img/20200624144922.png)



解密即可



```python
In [8]: a='njCp1HJBPLVTxcMhUHDPwE7mPW'

In [9]: c=''

In [10]: for i in range(len(a)):
    ...:     if not i%2==0:
    ...:         c+=chr(ord(a[i])+1)
    ...:     else:
    ...:         c+=chr(ord(a[i])-1)
    ...:         

In [11]: c
Out[11]: 'mkBq0IICOMUUwdLiTICQvF6nOX'
```



> flag{mkBq0IICOMUUwdLiTICQvF6nOX}