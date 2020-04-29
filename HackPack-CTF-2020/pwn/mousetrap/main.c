#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void cheeeeeeeese() {
    system("/bin/sh");
}

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void set_mouse_name(char* name)
{
    printf("Name: ");
    read(0,name,32);
    return;
}

void grab_cheese(char* sequence) {
    char decode[16];
    strcpy(decode,sequence);
    return;
}

void deactivate_trap(char* buffer, long size) 
{
    printf("Enter Code Sequence of %ld: ",size);
    read(0,buffer,size);
    return;
}

void menu(void) {
    printf("Welcome little mouse\n");
    printf("can you steal the cheese from the mouse trap\n");
    return;
}

int main(int argc,char** argv)
{
    long decode_size = 10;
    char mouse_name[16];
    char decode_sequence[256];
    init();
    menu();
    set_mouse_name(mouse_name); //this will lead the person to have control over the size variable
    deactivate_trap(decode_sequence,decode_size);
    grab_cheese(decode_sequence);
    printf("SNAAAAAAAP! you died!");
    return 0;
}

