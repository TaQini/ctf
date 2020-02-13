## SoulLike

- flag格式为actf{xxxxxxxxxxxx} (x=12)

```c
  for ( j = 0; j <= 11; ++j )
    buf[j] = flag[j + 5];
  v3 = (unsigned __int8)sub_83A(buf) && v12 == '}' ? 1 : 0;
  if ( v3 )
  {
    printf("That's true! flag is %s", flag);
    result = 0LL;
  }
```

- `sub_83A(buf)`这个函数贼长，汇编两万多行，不知道出题人怎么搞出来的。。。
- 略略的看一下，一堆异或操作，大概的操作是：
  - 将`xxxxxxxxxxxx`逐个字节反反复复的异或，最终和下面的正确结果比对：
   - 0x7E, 0x32, 0x25, 0x58, 0x59, 0x6B, 0x35, 0x6E, 0x0, 0x13, 0x1E, 0x38
 - xor太多了，于是尝试爆破，手动爆破又太累了，于是请出PIN来帮忙(滑稽)
## Pin指令数统计爆破
 - 逐字节爆破，由于输入正确flag与错误flag时，程序执行的指令数不同，因此可逐字节得出正确flag

 - 不想花时间自己写pintool，于是直接用pin新手教学中的`inscount0.so`

- 爆破时是这个亚子：

    ```shell
    % ./taqini.py
    solved: actf{b0Nf|Re_LiT
    solved:(maybe) actf{b0Nf|Re_LiTk
    solved:(maybe) actf{b0Nf|Re_LiTt
    solved:(maybe) actf{b0Nf|Re_LiTA
    solved:(maybe) actf{b0Nf|Re_LiTJ
    solved:(maybe) actf{b0Nf|Re_LiT!
    ```

- 由于编程能力太差，没法自动爆破，解出来的结果也不唯一，每个结果出来都要去gdb试一下

- 爆破脚本如下（写的很烂...师傅门凑合看）：

  ```python
  #!/usr/bin/python
  #__author__:TaQini
  
  import sys
  import string as s
  from subprocess import *
  import re
  
  #configure by the user
  PINBASEPATH = "/home/taqini/ctf_tools/pin-3.11-97998-g7ecce2dac-gcc-linux"
  PIN = "%s/pin" % PINBASEPATH
  INSCOUNT32 = "%s/source/tools/ManualExamples/obj-ia32/inscount0.so" % PINBASEPATH
  INSCOUNT64 = "%s/source/tools/ManualExamples/obj-intel64/inscount0.so" % PINBASEPATH
  INSCOUNT = INSCOUNT64
  
  def pin(passwd,filename):
      try:
          command = PIN + " -t " + INSCOUNT + " -- ./"+ filename + " ; cat inscount.out"
          p = Popen(command,shell=True,stderr=PIPE,stdin=PIPE,stdout=PIPE)
          output = p.communicate(input=passwd)[0]
      except:
          print "Unexpected error:", sys.exc_info()[0]
          raise
      output = re.findall(r"Count ([\w.-]+)", output)
  
      return int(''.join(output))
  
  filename = './SoulLike'
  charset='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()+,-./:;<=>?@[]^_`{|}~ '
  
  # append a char after right ...
  fix = 'actf{b0Nf|Re_LiT'
  
  print "solved: "+fix 
  while True:
      base = pin(fix+'a',filename)
      for i in charset:
          diff = abs(pin(fix+i,filename)-base)
          print i,"diff: %04d"%diff
          sys.stdout.write("\033[F")
          if diff >= 4: 
              print 'solved:(maybe)',fix+i
      fix += i
  
  ```

  