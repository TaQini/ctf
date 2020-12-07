#include<stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define MAXLEN 32
#define BAR_SIZE 8

char og_bars[BAR_SIZE];

void read_og_bars(){
    FILE *f = fopen("og_bars.txt", "r");
    if(f == NULL){
        printf("The OG bars are missing, either run the binary on the server or contact admin.\n");
        exit(0);
    }
    fread(og_bars, sizeof(char), BAR_SIZE, f);
    fclose(f);
}

void rap_battle(){
    char bars[BAR_SIZE];
    char buf[MAXLEN];
    char bar_len[MAXLEN];
    int count, x=0;

    memcpy(bars, og_bars, BAR_SIZE);
    puts("Can you defeat bobby in a rap battle?\n");
    printf("What's the size of your bars?\n");
    while(x<MAXLEN){
        read(0, bar_len+x, 1);
        if (bar_len[x] == '\n') break;
        x++;
    }
    sscanf(bar_len, "%d", &count);

    puts("Spit your bars here: ");

    read(0, buf, count);
    gets(buf);

    if(memcmp(bars, og_bars, BAR_SIZE)){
        printf("*** Stack Smashing Detected ***: The og bars were tampered with.\n");
        exit(-1);
    }
    fflush(stdout);
}

int main(){

    setvbuf(stdout, NULL, _IONBF, 0);
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

    read_og_bars();
     rap_battle();


    return 0;
}

