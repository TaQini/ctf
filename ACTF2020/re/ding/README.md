## ding

- 主要代码如下，其中`dest`位于`bss`段，`dest`函数在程序开启后初始化，所以静态分析不出来，要动态调

  ```c
  int __cdecl check(char *s)
  {
    signed int len_30; // [esp+4h] [ebp-14h]
    signed int i; // [esp+Ch] [ebp-Ch]

    if ( strlen(s) <= 0x10 )
      return 0;
    while ( !dest )
      sleep(1000u);
    (dest)(s);
    len_30 = strlen(enc_flag);
    for ( i = 0; i < len_30; ++i )
    {
      if ( i != len_30 - 1 && !s[i] || s[i] != enc_flag[i] )
        return 0;
    }
    return 1;
  }
  ```

- 由于用了多线程，直接用gdb调试的话不行

  ```shell
  pwndbg> b main
  Breakpoint 1 at 0xb56
  pwndbg> r
  Starting program: /home/taqini/Downloads/actf/re/Ding/ding 
  [Thread debugging using libthread_db enabled]
  Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
  [Attaching after Thread 0xf7fcf600 (LWP 32676) fork to child process 32680]
  [New inferior 2 (process 32680)]
  [Detaching after fork from parent process 32676]
  --- The quick brown fox knocked at the lazy dog's house ---
  [?]Password please:
  [Inferior 1 (process 32676) detached]
  [Thread debugging using libthread_db enabled]
  Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
  [New Thread 0xf7db0b40 (LWP 32685)]
  [Thread 0xf7db0b40 (LWP 32685) exited]
  [New Thread 0xf75afb40 (LWP 32686)]
  [Thread 0xf75afb40 (LWP 32686) exited]
  [Inferior 2 (process 32680) exited with code 01]
  ```

- 所以改用`gdb attach`：

  ```shell
  % ./ding 
  --- The quick brown fox knocked at the lazy dog's house ---
  [?]Password please:
  ^Z
  [1]  + 32732 suspended  ./ding
  
  % fg
  [1]  + 32732 continued  ./ding
  
  ```

  ```shell
  % gdb attach 32732 
  ```

- 动态调试的时候为了方便分析，dump出`dest()`函数

  ```shell
  pwndbg> dump binary memory 0x565790e0 0x5657914b
  ```

- 扔到ida反编译：

  ```c
  void __cdecl __noreturn sub_0(int a1)
  {
    int i; // [esp-8h] [ebp-8h]
  
    for ( i = 0; *(_BYTE *)(i + a1); ++i )
    {
      *(_BYTE *)(a1 + i) = *(_BYTE *)(i + a1) ^ 0x47;
      *(_BYTE *)(a1 + i) = *(_BYTE *)(i + a1) + 6;
      *(_BYTE *)(a1 + i) = *(_BYTE *)(i + a1) - 2;
    }
    JUMPOUT(MEMORY[0x6B]);
  }
  ```

  很简单的加密，解密脚本如下：

  ```python
  #！/usr/bin/python
  #__author__:TaQini
  
  enc_flag = [0x0A, 0x08, 0x17, 0x05, 0x40, 0x37, 0x33, 0x39, 0x26, 0x2A, 0x27, 0x1C, 0x32, 0x76, 0x1C, 0x25, 0x36, 0x2D, 0x1C, 0x7E, 0x39, 0x2A, 0x2D, 0x27, 0x73, 0x7A, 0x6F, 0x7A, 0x72, 0x3E]
  
  flag = []
  for i in enc_flag:
      flag.append(chr((i+2-6)^0x47))
  
  print ''.join(flag)
  ```

  

