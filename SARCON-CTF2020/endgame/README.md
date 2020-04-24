## The Endgame (500pt)

### Description

> Ok hackers it's time to wear your capes and get ready for the endgame. We will be analyzing a real malware now.This malware is being spread worldwide through COVID-19 related campaigns.
> Your task is to get us the name of the harmful executable file located in its strings and save the humanity from the malware. Your flag format is: secarmy{filename.exe}
> Warning:Although this is a static analysis, this is a real malware.You are advised to play this challenge in a virtual environment in order to avoid any damage/loss.
>
> Author:Umair9747
>

### Attachment

[12.exe](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SARCON-CTF2020/pwn/endgame/12.exe)

### Analysis

As the description say, our task is to get the **file name** of the harmful executable file located in its strings.

So, check what string in the executable file first. I use `radare2` cmd as follows:

```bash
rabin2 -zz 12.exe
```

In the end of its output, I saw the file named`tcgcQZrjffyIAPzmPfcQNoEQSJxlP.exe`

![](http://image.taqini.space/img/20200425001832.png)

I try to submit it and it is the real flag

> secarmy{tcgcQZrjffyIAPzmPfcQNoEQSJxlP.exe}

