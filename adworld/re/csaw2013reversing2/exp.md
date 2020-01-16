# hex
```
.data:00409B10 str36raw        dd 0BCA0CCBBh           ; DATA XREF: main+33↑o
.data:00409B14                 dd 0B8BED1DCh
.data:00409B18                 dd 0AEBECFCDh
.data:00409B1C                 dd 82ABC4D2h
.data:00409B20                 dd 0B393D9D2h
.data:00409B24                 dd 0A993DED4h
.data:00409B28                 dd 82B8CBD3h
.data:00409B2C                 dd 0B9BECBD3h
.data:00409B30                 dd 0DDCCD79Ah
.data:00409B34 ; rsize_t MaxCount
.data:00409B34 MaxCount        dd 36                   ; DATA XREF: main+18↑r
.data:00409B34                                         ; main+2D↑r ...
.data:00409B38 dword_409B38    dd 0DDCCAABBh  

# hex
00409B10  BB CC A0 BC DC D1 BE B8  CD CF BE AE D2 C4 AB 82
00409B20  D2 D9 93 B3 D4 DE 93 A9  D3 CB B8 82 D3 CB BE B9
00409B30  9A D7 CC DD 24 00 00 00  BB AA CC DD 00 00 00 00
```

# ipython
```
In [49]: s='BBCCA0BCDCD1BEB8CDCFBEAED2C4AB82D2D993B3D4DE93A9D3CBB882D3CBBEB99AD7CCDD'

In [50]: s2='BBAACCDD'

In [51]: l=[]

In [52]: for i in range(9):
    ...:     l.append('0x'+s[8*i:8*i+8])
    ...:     

In [53]: s2 = '0x'+s2

In [54]: flag=''

In [55]: for i in l:
    ...:     flag+=hex(eval(s2)^eval(i))[2:].decode('hex')
    ...:     

In [56]: flag
Out[56]: 'flag{reversing_is_not_that_hard!}\x00\x00'
```
