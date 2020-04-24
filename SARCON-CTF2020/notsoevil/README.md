
## The Game Of PDFs (0pt)
### Description

> Congratulations for solving the first step!
> Let's move on to the next one now! Here is a pdf i want you to look into.This file contains the flag script which i want you to discover!
> We recommend you to stick to command line! This one is very easy!
>
> Author:Umair9747
>

### Attachment

[notsoevil.pdf](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SARCON-CTF2020/pwn/notsoevil/notsoevil.pdf)

### Analysis

As the description say:

> We recommend you to stick to command line! This one is very easy!

I try `cat notsoevil.pdf` and find that:

```
/Type /Action
/S /JavaScript
/JS <69662028313C3029207B0A20206170702E616C657274282273656361726D797B315F7740246E375F337870336337316E675F7930755F37305F66316E645F6D337D22293B0A7D0A0A>
>>
```

Obviously, it is a string of hex encode.

### Solution

Decode then get the flag

```python
In [1]: a='69662028313C3029207B0A20206170702E616C657274282273656361726D797B315F7
   ...: 740246E375F337870336337316E675F7930755F37305F66316E645F6D337D22293B0A7D0
   ...: A0A'

In [2]: a.decode('hex')
Out[2]: 'if (1<0) {\n  app.alert("secarmy{1_w@$n7_3xp3c71ng_y0u_70_f1nd_m3}");\n}\n\n'
```

> flag: secarmy{1_w@$n7_3xp3c71ng_y0u_70_f1nd_m3}


