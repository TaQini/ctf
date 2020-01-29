# `pwn_base`
 - x86 elf | nx

 - 流程分析:
        - 输入一段`0x30`长度的字符串 , `base64` 后执行

 - 考察点:
        - ascll shellcode
        - alpha3
        - 因为长度限制,不能直接使用 msf 或者 alpha3 生成的shellcode

 - shellcode 要求
        - `read(0 , &sc , N)` ( `&sc` 为 第一段 `shellcode` 的 地址 , 存储在调用后的 `eax` 中 ， 目的是读入 第二段 `shellcode` | `N > len(shellcode1 + shellcode2))`
          
        1. 这段`shellcode` 要求全部由 base64的可用字符组成
        2. `pop ebx | inc eax ..` 等指令不可使用
        3. 查找 https://nets.ec/Ascii_shellcode
        4. `int 0x80` , 需要用 两个可见字符和寄存器中的值 异或或者做出其他的处理得出,考虑到长度限制，异或会是一个比较好的选择
        
        - 输入第二段shellcode即可

              1. 需要填充 前 `0x32` 个字符

                  

```
作者：fantasy_learner
链接：https://www.jianshu.com/p/07d1cd622b52
来源：简书
著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。
```
