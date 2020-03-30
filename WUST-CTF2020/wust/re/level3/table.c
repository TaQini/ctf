#include <stdio.h>
int main(){
  char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  int i;
  char v0,result;
  for ( i = 0; i <= 9; ++i )
  {
    v0 = base64_table[i];
    base64_table[i] = base64_table[19 - i];
    result = 19 - i;
    base64_table[result] = v0;
  }
  puts(base64_table);
  return result;
}