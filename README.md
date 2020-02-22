# Index of Pwn

- 总结一些做过的经典Pwn题目~

  

## Shell Code 

| 漏洞类型 | 知识点                          | 传送门                                                       |
| :------- | ------------------------------- | ------------------------------------------------------------ |
| 栈溢出   | `ASCII shellcode` (by `alpha3`) | [EasyShellcode](https://github.com/TaQini/ctf/tree/master/anheng/2020NewYear/pwn/unctf_EasyShellcode) |
| 栈溢出   | `栈迁移`/`shellcode`            | [Number_Killer](https://github.com/TaQini/ctf/tree/master/hgame2020/pwn/week1_2) |
| /        | `ASCII shellcode` (手动编码)    | [pwn-base](https://github.com/TaQini/ctf/tree/master/buuctf/Xman_2018_pwn-base) |
| /        | `nop sled`                      | [snow_mountain](https://github.com/TaQini/ctf/tree/master/MetasequoiaCTF/pwn/snow_mountain) |
| ...      | ...                             | ...                                                          |



## ROP

| 漏洞类型         | 知识点                        | 传送门                                                       |
| :--------------- | ----------------------------- | ------------------------------------------------------------ |
| `bof`            | 变量覆盖                      | [my_cannary](https://github.com/TaQini/ctf/tree/master/GXY_CTF_2019/pwn/my_cannary) |
| `bof`            | 无符号整数                    | [babystack2](https://github.com/TaQini/ctf/tree/master/BJDCTF/pwn/babystack2)/[blacksmith](https://github.com/TaQini/ctf/tree/master/MetasequoiaCTF/pwn/blacksmith) |
| 数组越界         | 盲打                          | [blind_note](https://github.com/TaQini/ctf/tree/master/GXY_CTF_2019/pwn/blind_note) |
| 数组越界         | /                             | [stack2](https://github.com/TaQini/ctf/tree/master/adworld/pwn/challenge/stack2) |
| `fsb`+`bof`      | 泄漏canary                    | [babyrop2](https://github.com/TaQini/ctf/tree/master/BJDCTF/pwn/babyrop2) |
| `fsb`+`bof`      | `printf_chk("%a")`/`do-while` | [chk_rop](https://github.com/TaQini/ctf/tree/master/ACTF2020/pwn/unsolved/chk_rop) |
| `bof`            | `ret2dl_resolve`              | [bof](https://github.com/TaQini/ctf/tree/master/r2dl)        |
| `bof`            | 爆破+`ret2dl_resolve`         | [stack](https://github.com/TaQini/ctf/tree/master/京津冀2019线下) |
| `bof`(`8 bytes`) | 栈迁移                        | [welpwn](https://github.com/TaQini/ctf/tree/master/adworld/pwn/challenge/welpwn) |
| `bof`(`8 bytes`) | 栈迁移+`seccomp(0x3b)`        | [ROP](https://github.com/TaQini/ctf/tree/master/hgame2020/pwn/week3_1) |
| `bof`+栈地址泄漏 | 栈迁移(扩大栈空间)            | [es2](https://github.com/TaQini/ctf/tree/master/buuctf/ciscn/es2) |
| ...              | ...                           | ...                                                          |



## One Gadget

| 漏洞类型    | 知识点     | 传送门                                                       |
| ----------- | ---------- | ------------------------------------------------------------ |
| 栈泄漏+改写 | one_gadget | [week2_4](https://github.com/TaQini/ctf/tree/master/hgame2020/pwn/week2_4) |
| ...         | ...        | ...                                                          |



## GOT overwrite

| 漏洞类型 | 知识点  | 传送门                                             |
| -------- | ------- | -------------------------------------------------- |
| 任意写   | GOT覆写 | [week2_3](https://github.com/TaQini/ctf/tree/master/hgame2020/pwn/week2_3) |
| ... | ... | ... |



## Format String 

| 漏洞类型    | 知识点                               | 传送门                                                       |
| ----------- | ------------------------------------ | ------------------------------------------------------------ |
| `fsb`       | `%n`                                 | [CGfsb](https://github.com/TaQini/ctf/tree/master/adworld/pwn/exercise/CGfsb)/[fmt32](https://github.com/TaQini/ctf/tree/master/ACTF2020/pwn/fmt32) |
| `fsb`+`bof` | 泄漏canary                           | [babyrop2](https://github.com/TaQini/ctf/tree/master/BJDCTF/pwn/babyrop2) |
| `fsb`       | [全保护]修改libc函数指针/`free_hook` | [fmt64](https://github.com/TaQini/ctf/tree/master/ACTF2020/pwn/fmt64) |
| ...         | ...                                  | ...                                                          |



## Double free

| 漏洞类型      | 知识点              | 传送门                                                       |
| ------------- | ------------------- | ------------------------------------------------------------ |
| `double free` | 伪造chunk           | [samsara](https://github.com/TaQini/ctf/tree/master/MetasequoiaCTF/pwn/samsara) |
| `double free` | `unsorted bin leak` | [week2_2](https://github.com/TaQini/ctf/tree/master/hgame2020/pwn/week2_2) |
| ...           | ...                 | ...                                                          |



## fastbin attack

| 漏洞类型       | 知识点             | 传送门                                                       |
| -------------- | ------------------ | ------------------------------------------------------------ |
| fastbin attack | malloc内存分配机制 | [Summoner](https://github.com/TaQini/ctf/tree/master/MetasequoiaCTF/pwn/Summoner) |
|                |                    |                                                              |
| ...            | ...                | ...                                                          |



## IO_FILE attack

| 漏洞类型 | 知识点      | 传送门                                                       |
| -------- | ----------- | ------------------------------------------------------------ |
| 数组越界 | 修改IO_FILE | [complaint](https://github.com/TaQini/ctf/tree/master/ACTF2020/pwn/complaint) |
|          |             |                                                              |
| ...      | ...         | ..                                                           |



## About Linux shell cmd

| 漏洞类型 | 知识点                                  | 传送门                                  |
| -------- | --------------------------------------- | --------------------------------------- |
| /        | 绕过命令过滤+`stdout`重定向+`ls -i`命令 | [find_yourself](hgame2020/pwn/week2_1 ) |
| 命令注入 | 逆向分析+指令链接符号 `;`               | [dizzy](https://github.com/TaQini/ctf/tree/master/BJDCTF/pwn/dizzy)             |
| 命令注入 | 指令链接符号 `;`                        | [babyrouter](https://github.com/TaQini/ctf/tree/master/BJDCTF/pwn/babyrouter)   |
| ...      | ...                                     | ...                                     |





## Statically Linked

| 漏洞类型 | 知识点                                | 传送门                              |
| -------- | ------------------------------------- | ----------------------------------- |
| 栈溢出   | `mprotect`/`ROPgadget --static`/`ROP` | [3dsctf_2016](https://github.com/TaQini/ctf/tree/master/buuctf/3dsctf_2016) |
| 任意写   | `ROP`/`fini_array劫持`/`栈迁移`       | [3x17](https://github.com/TaQini/ctf/tree/master/pwnable_tw/3x17)           |
| ...      | ...                                   | ...                                 |



## Other

| 漏洞类型   | 知识点                          | 传送门                                                       |
| ---------- | ------------------------------- | ------------------------------------------------------------ |
| 缓冲区溢出 | 变量覆盖+`ctypes`调用`Libc`函数 | [guess_num](https://github.com/TaQini/ctf/tree/master/adworld/pwn/exercise/guess_num)                |
| 路径穿越   | (WEB) HTTP协议                  | [httpd](https://github.com/TaQini/ctf/tree/master/GXY_CTF_2019/pwn/httpd)                            |
| 栈溢出     | (Crypto) RSA加密                | [encrypted_stack](https://github.com/BjdsecCA/BJDCTF2020/tree/master/Pwn/encrypted_stack/poc) |
| ...        | ...                             | ...                                                          |



