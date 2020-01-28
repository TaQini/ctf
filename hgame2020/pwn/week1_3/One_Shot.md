```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _BYTE *v4; // [rsp+8h] [rbp-18h]
  int fd[2]; // [rsp+10h] [rbp-10h]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v4 = 0LL;
  *(_QWORD *)fd = open("./flag", 0, envp);
  setbuf(stdout, 0LL);
  read(fd[0], &flag, 0x1EuLL);
  puts("Firstly....What's your name?");
  __isoc99_scanf("%32s", &name);
  puts("The thing that could change the world might be a Byte!");
  puts("Take tne only one shot!");
  __isoc99_scanf("%d", &v4);
  *v4 = 1;
  puts("A success?");
  printf("Goodbye,%s", &name);
  return 0;
}
```
