# Index of Pwn

- 总结一些做过的经典Pwn题目~

  

## Shell Code 

| 漏洞类型 | 知识点                          | 传送门                                                       |
| -------- | ------------------------------- | ------------------------------------------------------------ |
| 栈溢出   | `ASCII shellcode` (by `alpha3`) | [EasyShellcode](./anheng/2020NewYear/pwn/unctf_EasyShellcode) |
| 栈溢出   | `栈迁移`/`shellcode`            | [Number_Killer](./hgame2020/pwn/week1_2)                     |
| /        | `ASCII shellcode` (手动编码)    | [pwn-base](./buuctf/Xman_2018_pwn-base)                      |
|          |                                 |                                                              |



## ROP

| 漏洞类型              | 知识点                | 传送门                                      |
| :-------------------- | --------------------- | ------------------------------------------- |
| 缓冲区溢出            | 变量覆盖              | [my_cannary](./GXY_CTF_2019/pwn/my_cannary) |
| 数组越界              | 盲打                  | [blind_note](./GXY_CTF_2019/pwn/blind_note) |
| 缓冲区溢出            | 无符号整数            | [babystack2](./BJDCTF/pwn/babystack2)       |
| 格式化字符串+`bof`    | 泄漏canary            | [babyrop2](./BJDCTF/pwn/babyrop2)           |
| 缓冲区溢出            | `ret2dl_resolve`      | [bof](/.r2dl)                               |
| 缓冲区溢出            | 爆破+`ret2dl_resolve` | [stack](./京津冀2019线下
)                   |
| 数组越界              | /                     | [stack2](./adworld/pwn/challenge/stack2)    |
| 缓冲区溢出(`8 bytes`) | 栈迁移                | [welpwn](./adworld/pwn/challenge/welpwn)    |
| 缓冲区溢出+栈地址泄漏 | 栈迁移(到缓冲区)      | [es2](./buuctf/ciscn/es2)                   |
|                       |                       |                                             |



## One Gadget

| 漏洞类型    | 知识点     | 传送门                                             |
| ----------- | ---------- | -------------------------------------------------- |
| 栈泄漏+改写 | one_gadget | [./hgame2020/pwn/week2_4](./hgame2020/pwn/week2_4) |
|             |            |                                                    |



## GOT overwrite

| 漏洞类型 | 知识点  | 传送门                                             |
| -------- | ------- | -------------------------------------------------- |
| 任意写   | GOT覆写 | [./hgame2020/pwn/week2_3](./hgame2020/pwn/week2_3) |
|          |          |                                                              |



## Format String 

| 漏洞类型    | 知识点     | 传送门                                |
| ----------- | ---------- | ------------------------------------- |
| `fsb`       | `%n`       | [CGfsb](./adworld/pwn/exercise/CGfsb) |
| `fsb`+`bof` | 泄漏canary | [babyrop2](./BJDCTF/pwn/babyrop2)     |
|             |            |                                       |



## About Linux shell cmd

| 漏洞类型 | 知识点                                  | 传送门                                  |
| -------- | --------------------------------------- | --------------------------------------- |
| /        | 绕过命令过滤+`stdout`重定向+`ls -i`命令 | [find_yourself](hgame2020/pwn/week2_1 ) |
| 命令注入 | 逆向分析+指令链接符号 `;`               | [dizzy](./BJDCTF/pwn/dizzy)             |
| 命令注入 | 指令链接符号 `;`                        | [babyrouter](./BJDCTF/pwn/babyrouter)   |
|          |                                         |                                         |



## Statically Linked

| 漏洞类型 | 知识点                                | 传送门                              |
| -------- | ------------------------------------- | ----------------------------------- |
| 栈溢出   | `mprotect`/`ROPgadget --static`/`ROP` | [3dsctf_2016](./buuctf/3dsctf_2016) |
| 任意写   | `ROP`/`fini_array劫持`/`栈迁移`       | [3x17](./pwnable_tw/3x17)           |
|          |                                       |                                     |
|          |                                       |                                     |



## Other

| 漏洞类型   | 知识点                          | 传送门                                                       |
| ---------- | ------------------------------- | ------------------------------------------------------------ |
| 缓冲区溢出 | 变量覆盖+`ctypes`调用`Libc`函数 | [guess_num](./adworld/pwn/exercise/guess_num)                |
| 路径穿越   | (WEB) HTTP协议                  | [httpd](./GXY_CTF_2019/pwn/httpd)                            |
| 栈溢出     | (Crypto) RSA加密                | [encrypted_stack](https://github.com/BjdsecCA/BJDCTF2020/tree/master/Pwn/encrypted_stack/poc) |
|            |                                 |                                                              |

