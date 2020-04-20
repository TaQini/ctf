## LynxVE (50pt)

### Description

> `ssh ctf@lynxve.wpictf.xyz` 
>
> pass: `lynxVE` 
>
> made by: acurless

### Analysis

> [Lynx](https://lynx.invisible-island.net/) is a text Web-Browser 

We can visit local files in this browser by `file://` protocol:

```bash
file://localhost/etc/fstab
file:///etc/fstab
```

> Examples from [wikipedia](https://en.wikipedia.org/wiki/File_URI_scheme#Unix)

### Solution

Type `G` and input URL=`file:///` to visit local files:

![](http://image.taqini.space/img/20200419021852.png)

Finally we can find `flag` in folder `/home/ctf/` and then read it:

![](http://image.taqini.space/img/20200419021518.png)

> WPI{lynX_13_Gr8or_Th@n_Chr0m1Um}

