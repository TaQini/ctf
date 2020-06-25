#include<stdlib.h>
#include<stdio.h>
#include<unistd.h>
#define NUM 0x10

char* chunks[NUM];

unsigned long cookie;

#define SIZE 0x100

void init_io(){
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    int fd = open("/dev/urandom", 0);
    if(fd == -1){
        exit(-1);
    }
    read(fd, &cookie, 8);
    close(fd);
}

unsigned long get_int(){
    unsigned long res;
    scanf("%ld", &res);
    return res;
}

void allocate(){
    unsigned long idx;
    printf("Index: ");
    idx = get_int(); 
    if(idx >= NUM){
        return ;
    }

    
    char* buf = malloc(SIZE);
    if(buf == NULL){
        puts("allocate failed");
        return;
    }
    chunks[idx] = buf;
    unsigned long* p = chunks[idx] + SIZE - 8;
    *p = cookie;
    puts("Done!");
}

void delete(){
    unsigned long idx;
    printf("Index: ");
    idx = get_int(); 
    if(idx >= NUM || chunks[idx] == NULL){
        return ;
    }
    
    unsigned long* p = chunks[idx] + SIZE - 8;
    if(*p != cookie) return;
    *p = 0;
    free(chunks[idx]);
}

void show(){
    unsigned long idx;
    printf("Index: ");
    idx = get_int(); 
    if(idx >= NUM || chunks[idx] == NULL){
        return ;
    }
    
    unsigned long* p = chunks[idx] + SIZE - 8;
    if(*p != cookie) return;

    write(1, "Content: ", strlen("Content: "));
    write(1, chunks[idx], SIZE - 8);
    write(1, "\n", 1);
}

void edit(){
    unsigned long idx;
    printf("Index: ");
    idx = get_int(); 
    if(idx >= NUM || chunks[idx] == NULL){
        return ;
    }
    unsigned long* p = chunks[idx] + SIZE - 8;
    if(*p != cookie) return;
    
    printf("Content: ");
    read(0, chunks[idx], SIZE);
}

void menu(){
    puts("1. allocate");
    puts("2. edit");
    puts("3. show");
    puts("4. delete");
    puts("5. exit");
    printf("Your choice: ");
}

int main(){
    init_io();
    puts("Made on Ubuntu 18.04");
    while(1){
        menu();
        unsigned long choice = get_int();
        switch(choice){
            case 1:
                allocate();
                break;
            case 2:
                edit();
                break;
            case 3:
                show();
                break;
            case 4:
                delete();
                break;
            case 5:
                exit(0);
                break;
            default:
                puts("Unknown");
                break;
        }
    }
    return 0;
}
