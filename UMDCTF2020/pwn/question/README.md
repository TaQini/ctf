
## question
### Description

> To read or not to read the flag... That is the question!
>
> `nc 192.241.138.174 9999` 
>
> Author: `lumpus`

### Analysis

We can't `cat flag.txt` directly (maybe `flag` was filtered.)

```bash
The flag.txt is here. Try to read it!
> cat flag.txt
Nope!
```

### Solution

Use  **wildcard** character to bypass check:

```bash
> cat ????????
UMDCTF-{s0me_questions_h4ve_answ3rs}
```

> question mark (?) represents any single character

