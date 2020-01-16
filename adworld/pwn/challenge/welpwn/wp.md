# RCTF-2015 welpwna
```
int __fastcall echo(__int64 a1)
{
  char s2[16]; // [rsp+10h] [rbp-10h]

  for ( i = 0; *(_BYTE *)(i + a1); ++i )
    s2[i] = *(_BYTE *)(i + a1);
  s2[i] = 0;
  if ( !strcmp("ROIS", s2) )
  {
    printf("RCTF{Welcome}", s2);
    puts(" is not flag");
  }
  return printf("%s", s2);
}
```
 - |`s2`(0x10)|`old_ebp`(0x8)|`ret`(0x8)|buf(0x400)|
 - 溢出点在`s2`,但是有截断(`\x00`),只能写进去一个p64(),但是`s2`挨着`main`的`buf`,所以`p64(p4r)`即可将栈迁移至`buf`
 - `buf`通过`read`读入，无截断

