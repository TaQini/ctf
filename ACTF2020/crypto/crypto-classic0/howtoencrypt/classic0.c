#include<stdio.h>

char flag[25] = ***

int main()
{
	int i;
	for(i=0;i<25;i++)
	{
		flag[i] -= 3;
		flag[i] ^= 0x7;
		printf("%c",flag[i]);
	}
	return 0; 
}
