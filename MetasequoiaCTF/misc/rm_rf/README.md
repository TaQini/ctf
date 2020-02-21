## rm -rf /

- 题目描述：

  > 出题人不会出题，只好把系统命令删了让大家来猜flag。 
  >
  > 注：请使用`nc`连接容器，浏览器访问是无效的。 
  >
  > By *FLAG挖掘机* 					
  
 - 考察点：linux命令、shell编程

 - 难度：简单

 - 初始分值：250

 - 最终分值：244

 - 完成人数：3

### 非预期

`nc`连过去，有一次执行命令的机会，直接执行sh即可拿到shell

看了下`/bin`目录下的文件，删除了有输出功能的`cat`、`grep`等命令，不过`sh`还在，只要` sh .flag`，就能从`stderr`中读到flag

> sh 会逐条执行文本中的命令，命令不存在时会报错 e.g.
>
> ```shell
> $ sh txt 
> txt: 1: txt: xxxx: not found
> ```



### 官方解

出题人背锅的一道题，存在很多非预期解。

预期解法是

```shell
while read -r line;do echo $line;done</.flag
```

但实际做下来发现，因为没有对输入进行限制，`sed`等命令就可以读到flag。删去的命令基本上是`cat, grep, head,more, tail, less, base64`等，其实还删去了`/usr/bin/`下的内容。

