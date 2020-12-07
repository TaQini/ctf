#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char const *argv[]) {
    void *mem1;
    void *mem2;
    void **addr;
    void *leak;
    setvbuf(stdout,0,2,0);
    alarm(60);
    printf("Gift: %p\n",&alarm);
    write(1, "where to read?:", 15);
    read(0,&addr,8);
    write(1,"data: ",6);
    write(1,addr ,8);
    write(1, "where to write?:", 16);
    read(0,&addr,8);
    mem1 = malloc(0x30);
    write(1, "msg: ",5);
    read(0, mem1, 0x30-1);
    //sleep(10);
    *addr = mem1;
    return 0;
}
