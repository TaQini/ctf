// signed __int64 __fastcall check1(const char *cmd)
// {
//   signed __int64 result; // rax
//   int i; // [rsp+1Ch] [rbp-14h]

//   for ( i = 0; i < strlen(cmd); ++i )
//   {
//     if ( (cmd[i] <= '`' || cmd[i] > 'z')
//       && (cmd[i] <= '@' || cmd[i] > 'Z')
//       && cmd[i] != '/'
//       && cmd[i] != ' '
//       && cmd[i] != '-' )
//     {
//       return 0xFFFFFFFFLL;
//     }
//   }
//   if ( strstr(cmd, "sh") || strstr(cmd, "cat") || strstr(cmd, "flag") || strstr(cmd, "pwd") || strstr(cmd, "export") )
//     result = 0xFFFFFFFFLL;
//   else
//     result = 0LL;
//   return result;
// }
#include <stdio.h>
int main(){
  char i;
  for(i='`'+1;i<='z';i++){
    printf("%c ", i);
    // putchar(i);
  }
  puts("");
  for(i='@'+1;i<='Z';i++){
    printf("%c ", i);
    // printf("%d\n", a);
  }
  puts("");
  puts("/   - ");
  puts("sh ");
  puts("cat ");
  puts("flag ");
  puts("pwd ");
  puts("export ");
}

// check1: ???? how to get word direction??????
// check2: a=t;b=ag;ca$a fl$b
