#include <stdlib.h>
#include <stdio.h>
#include <string.h>

  int main(int argc, char *argv[]){
    char buffer[128];
    strcpy(buffer,  argv[1]);
    int (*ret)() = (int(*)())buffer;
    ret();
}
