## simple
> A really simple crackme to get started ;) Your goal is to find the correct input so that the program return 1. The correct input will be the flag.
> 
> Creator : Nofix

### source code

```nasm
BITS 64

SECTION .rodata
	some_array db 10,2,30,15,3,7,4,2,1,24,5,11,24,4,14,13,5,6,19,20,23,9,10,2,30,15,3,7,4,2,1,24
	the_second_array db 0x57,0x40,0xa3,0x78,0x7d,0x67,0x55,0x40,0x1e,0xae,0x5b,0x11,0x5d,0x40,0xaa,0x17,0x58,0x4f,0x7e,0x4d,0x4e,0x42,0x5d,0x51,0x57,0x5f,0x5f,0x12,0x1d,0x5a,0x4f,0xbf
	len_second_array equ $ - the_second_array
SECTION .text
    GLOBAL main

main:
	mov rdx, [rsp]
	cmp rdx, 2
	jne exit
	mov rsi, [rsp+0x10]
	mov rdx, rsi
	mov rcx, 0
l1:
	cmp byte [rdx], 0
	je follow_the_label
	inc rcx
	inc rdx
	jmp l1
follow_the_label:
	mov al, byte [rsi+rcx-1]
	mov rdi,  some_array
	mov rdi, [rdi+rcx-1]
	add al, dil
	xor rax, 42
	mov r10, the_second_array
	add r10, rcx
	dec r10
	cmp al, byte [r10]
	jne exit
	dec rcx
	cmp rcx, 0
	jne follow_the_label
win:
	mov rdi, 1
	mov rax, 60
	syscall
exit:
	mov rdi, 0
	mov rax, 60
	syscall
```

### compile

```shell
% nasm main.asm -f elf64
% gcc main.o -o simple
```

### decompile

```c
while ( ((*(&some_array + v4 - 1) + v7[v4 - 1]) ^ 0x2A) == the_second_array[v4 - 1] ){
    if ( !--v4 ) {
        __asm { syscall; LINUX - sys_exit }
        break;
    }
}
```

### re-write the code

```c
int main(){
    char some_array[] = {10,2,30,15,3,7,4,2,1,24,5,11,24,4,14,13,5,6,19,20,23,9,10,2,30,15,3,7,4,2,1,24};
    char the_second_array[] = {0x57,0x40,0xa3,0x78,0x7d,0x67,0x55,0x40,0x1e,0xae,0x5b,0x11,0x5d,0x40,0xaa,0x17,0x58,0x4f,0x7e,0x4d,0x4e,0x42,0x5d,0x51,0x57,0x5f,0x5f,0x12,0x1d,0x5a,0x4f,0xbf};
    char v7[33];
    int i=32;
    while (i){
        v7[i - 1] = (the_second_array[i - 1] ^ (char)0x2A) - some_array[i - 1];
        i--;
    }
    puts(v7);
}
```

### compile & run

```
% gcc simple.c -o solve
% ./solve 
shkCTF{h3ll0_fr0m_ASM_my_fr13nd}
```

### More

you can download all files from my [github](https://github.com/TaQini/ctf/tree/master/SharkyCTF-2020/re/simple) 


