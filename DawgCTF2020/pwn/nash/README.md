
## Nash
### Description

> Welcome to Nash! It's a NoSpaceBash! All you have to do is display the flag. It's right there.
>
> ```
> cat flag.txt
> ```
>
> Oh yeah...you can't use any spaces... Good luck!
>
> nc [ctf.umbccd.io](http://ctf.umbccd.io/) 4600
>
> Author: BlueStar

### Analysis

`spaces` was removed while trying to `cat flag.txt`:

```bash
nash> cat flag.txt
/bin/bash: line 1: catflag.txt: command not found
```

### Solution

We can use `<` to redirect the contents of `flag.txt` to the standard input (`stdin`) of `cat` command.

```bash
nash> cat<flag.txt
DawgCTF{L1k3_H0W_gr3a+_R_sp@c3s_Th0uGh_0mg}
```

### More

We can also download `nash` by following command:

```bash
nash> cat<nash
```

output:

```bash
#!/bin/bash
EXIT="exit"

while [ 1 ]
do
	read -p 'nash> ' input
	echo $input | sed 's/ //g' | sed 's/{//g'| sed 's/}//g' | sed 's/IFS//g' | sed 's/(//g' | sed 's/)//g' | /bin/bash
done
```

We can see `IFS`,`{`,`}`,`(` and `)` in our input were filtered, so `cat$IFSflag.txt` or `cat${IFS}flag.txt` doesn't work.

you can download all files from my [github](https://github.com/TaQini/ctf/tree/master/DawgCTF2020/pwn/nash) 

### Tricks of bash redirections

![](http://image.taqini.space/img/20200411100454.png)

[Reference](https://github.com/pkrumins/bash-redirections-cheat-sheet/blob/master/bash-redirections-cheat-sheet.png)