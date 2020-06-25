
有三个反调试函数 `0x0804857b`,`0x080485c4`, `0x0804865b`，直接全部nop掉。得到main函数如下：

```c
void main(undefined4 param_1, undefined4 *param_2){
    fcn.0804865b(*param_2);
    puts("input your flag");
    __isoc99_scanf(0x8048832, 0x804a038);
    *(int32_t *)0x804a038 = *(int32_t *)0x804a038 + 1;
    fcn.0804857b();
    *(int32_t *)0x804a038 = *(int32_t *)0x804a038 + 1;
    fcn.080485c4();
    *(int32_t *)0x804a038 = *(int32_t *)0x804a038 + -0x33333334;
    fcn.080485c4();
    *(int32_t *)0x804a038 = *(int32_t *)0x804a038 + 1;
    fcn.080485c4();
    // WARNING: Could not recover jumptable at 0x08048751. Too many branches
    // WARNING: Treating indirect jump as call
    (*(code *)0x8048753)();
    return;
}
```

`0x804a038`是flag，是个有符号的整型数，随便瞎输入个数字，就直接报错了：

```bash
% ./new 
input your flag
2333
[1]    17904 segmentation fault (core dumped)  ./new
```

调试一下发现`0x804a038`最终的值必须得是一个指针。

`0x8048753`处的函数是将`0x804a038`中指针指向的地址的两字节nop掉。

![image-20200624162314843](/home/taqini/.config/Typora/typora-user-images/image-20200624162314843.png)

![image-20200624164200292](/home/taqini/.config/Typora/typora-user-images/image-20200624164200292.png)

默认是执行`jmp 0x8048779` 跳转到输出wrong，需要把这两字节的指令nop掉，才会输出right

根据代码可以得到

> flag+1+1-0x33333334+1 = 0x8048765

解得flag = 993507990

> flag{993507990}