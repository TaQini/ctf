#include <stdio.h>
int main(){
    int new_len, len;
    for(len=0;len<=16;len++){
        new_len = 3 * len - 48 * ((0xAAAAAAAAAAAAAAABLL * (unsigned)(3 * len) >> 64) >> 5);
        printf("%02d-%03d\n",len,new_len);
    }
}
