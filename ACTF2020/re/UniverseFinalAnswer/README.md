## UniverseFinalAnswer

解十元一次方程组，输入的字符串作为十个变量

虽然flag由两部分组成，但是看程序逻辑，只要解方程对了就可以

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 v4; // [rsp+0h] [rbp-A8h]
  char key_string; // [rsp+20h] [rbp-88h]
  unsigned __int64 v6; // [rsp+88h] [rbp-20h]

  v6 = __readfsqword(0x28u);
  __printf_chk(1LL, "Please give me the key string:", a3);
  scanf("%s", &key_string);
  if ( equation(&key_string) )
  {
    key_xor_to_int_str(&key_string, &key_string, &v4);
    // key_string 按位异或,再异或9，十进制结果转为字符串作为printf第4个参数,并没有什么用
    __printf_chk(1LL, "Judgement pass! flag is actf{%s_%s}\n", &key_string);
  }
  else
  {
    puts("False key!");
  }
  return 0LL;
}
```

 - part1:方程的十个变量
 - part2:十个变量异或再异或9后的结果
 - flag格式:`actf{part1_part2}`

### 解方程

```c
bool __fastcall formal(char *a1)
{
  int x2; // ecx
  int x1; // esi
  int x3; // edx
  int x4; // er9
  int x5; // er11
  int x7; // ebp
  int x6; // ebx
  int x8; // er8
  int x9; // er10
  bool result; // al
  int x10; // [rsp+0h] [rbp-38h]

  x2 = a1[1];
  x1 = *a1;
  x3 = a1[2];
  x4 = a1[3];
  x5 = a1[4];
  x7 = a1[6];
  // 此处想打出题人,x6,x7居然反着写，导致解方程一直不对，我debug了半天才找出来。。。
  x6 = a1[5];
  x8 = a1[7];
  x9 = a1[8];
  result = 0;
  if ( -85 * x9 + 58 * x8 + 97 * x7 + x6 + -45 * x5 + 84 * x4 + 95 * x1 - 20 * x2 + 12 * x3 == 12613 )
  {
    x10 = a1[9];
    if ( 30 * x10 + -70 * x9 + -122 * x7 + -81 * x6 + -66 * x5 + -115 * x4 + -41 * x3 + -86 * x2 - 15 * x1 - 30 * x8 == -54400
      && -103 * x10 + 120 * x8 + 108 * x6 + 48 * x4 + -89 * x3 + 78 * x2 - 41 * x1 + 31 * x5 - (x7 << 6) - 120 * x9 == -10283
      && 71 * x7 + (x6 << 7) + 99 * x5 + -111 * x3 + 85 * x2 + 79 * x1 - 30 * x4 - 119 * x8 + 48 * x9 - 16 * x10 == 22855
      && 5 * x10 + 23 * x9 + 122 * x8 + -19 * x7 + 99 * x6 + -117 * x5 + -69 * x3 + 22 * x2 - 98 * x1 + 10 * x4 == -2944
      && -54 * x10 + -23 * x8 + -82 * x3 + -85 * x1 + 124 * x2 - 11 * x4 - 8 * x5 - 60 * x6 + 95 * x7 + 100 * x9 == -2222
      && -83 * x10 + -111 * x6 + -57 * x1 + 41 * x2 + 73 * x3 - 18 * x4 + 26 * x5 + 16 * x7 + 77 * x8 - 63 * x9 == -13258
      && 81 * x10 + -48 * x9 + 66 * x8 + -104 * x7 + -121 * x6 + 95 * x5 + 85 * x4 + 60 * x3 + -85 * x1 + 80 * x2 == -1559
      && 101 * x10 + -85 * x9 + 7 * x7 + 117 * x6 + -83 * x5 + -101 * x4 + 90 * x3 + -28 * x2 + 18 * x1 - x8 == 6308 )
    {
      result = 99 * x10 + -28 * x9 + 5 * x8 + 93 * x7 + -18 * x6 + -127 * x5 + 6 * x4 + -9 * x3 + -93 * x2 + 58 * x1 == -1697;
    }
  }
  return result;
}
```

- 提取出十个方程，用python解方程即可，这里比较坑的是出题人把`x6`和`x7`的顺序换了一下，不仔细看的话，会把这两个变量搞反。。。我就搞反了，debug的时候第一个方程总是解不对，曾一度怀疑是c语言运算出问题了。。。。（出题人，哪里跑！）

  ```python
  #!/usr/bin/python
  #__author__:TaQini
  
  import sympy
  
  x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10 = sympy.symbols("x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10")
  
  b = sympy.solve(
      [-85*x9+58*x8+97*x7+x6+-45*x5+84*x4+95*x1-20*x2+12*x3-12613,
      30*x10+-70*x9+-122*x7+-81*x6+-66*x5+-115*x4+-41*x3+-86*x2-15*x1-30*x8+54400,
      -103*x10+120*x8+108*x6+48*x4+-89*x3+78*x2-41*x1+31*x5-(x7*64)-120*x9+10283,
      71*x7+(x6*128)+99*x5+-111*x3+85*x2+79*x1-30*x4-119*x8+48*x9-16*x10-22855,
      5*x10+23*x9+122*x8+-19*x7+99*x6+-117*x5+-69*x3+22*x2-98*x1+10*x4+2944,
      -54*x10+-23*x8+-82*x3+-85*x1+124*x2-11*x4-8*x5-60*x6+95*x7+100*x9+2222,
      -83*x10+-111*x6+-57*x1+41*x2+73*x3-18*x4+26*x5+16*x7+77*x8-63*x9+13258,
      81*x10+-48*x9+66*x8+-104*x7+-121*x6+95*x5+85*x4+60*x3+-85*x1+80*x2+1559,
      101*x10+-85*x9+7*x7+117*x6+-83*x5+-101*x4+90*x3+-28*x2+18*x1-x8-6308,
      99*x10+-28*x9+5*x8+93*x7+-18*x6+-127*x5+6*x4+-9*x3+-93*x2+58*x1+1697],
      [x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x0]    
  )
  print dict(b)
  
  d = {"x3": 117, "x7": 95, "x10": 64, "x9": 119, "x2": 48, "x6": 121, "x4": 82, "x1": 70, "x8": 55, "x5": 84}
  
  part1 = chr(d["x1"])+chr(d["x2"])+chr(d["x3"])+chr(d["x4"])+chr(d["x5"])+chr(d["x6"])+chr(d["x7"])+chr(d["x8"])+chr(d["x9"])+chr(d["x10"])
  # print hex(d["x1"]),hex(d["x2"]),hex(d["x3"]),hex(d["x4"]),hex(d["x5"]),hex(d["x6"]),hex(d["x7"]),hex(d["x8"]),hex(d["x9"]),hex(d["x10"])
  part2 = 9
  for i in d:
  	part2 ^= d[i]
  part2 = str(part2)
  
  print "actf{%s_%s}"%(part1,part2)
  ```

- p.s.这题其实给9个方程就可以做，因为变量必然是Ascii。