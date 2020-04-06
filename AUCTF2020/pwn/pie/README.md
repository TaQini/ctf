## Easy as Pie!

### Description

> My friend just spent hours making this custom shell! He's still working on it so it doesn't have much. But we can do some stuff! He even built a custom access control list for controlling if you can access files.
>
> Check it out!
>
> nc challenges.auctf.com 30010
>
> Author: kensocolo

### Analysis

access to the python shell and type `help`:

```bash
% nc challenges.auctf.com 30010
Welcome to my custom shell written in Python! To get started type `help`
user@pyshell$ help

Use help <command> for help on specific command.
================================================
cat  help  ls  write

```

try `ls` command:

```bash
user@pyshell$ ls
acl.txt
user.txt
flag.txt
```

here are 3 files, try to `cat` them:

```bash
user@pyshell$ cat flag.txt
Don't have da permzzz
user@pyshell$ cat user.txt
this is some user content. I bet u wish the flag was here
user@pyshell$ cat acl.txt
user.txt:user:600
.acl.txt:root:600
.flag.txt:user:600
flag.txt:root:600
acl.txt:root:606
user@pyshell$ cat .flag.txt
nope not here sorry :)
user@pyshell$ cat .acl.txt
Don't have da permzzz
```

>  we can see two hidden files after `cat acl.txt`

the owner of both `flag.txt` and `.acl.txt` are `root` and the privileges are `600`, so only root can read them.

maybe `acl.txt` means **a**ccess **c**ontro**l**?

type `help write`, we can find that the `write` command can add lines to the beginning of files

```bash
user@pyshell$ help write   

        write <content> <filename>
        adds content to the beginning of the file.
       
```

so, try to add access control rules to `acl.txt`

```bash
user@pyshell$ write flag.txt:user:666 acl.txt
flag.txt:user:666
user@pyshell$ write .acl.txt:user:666 acl.txt
.acl.txt:user:666
```

`cat` is work after rules added:

```bash
user@pyshell$ cat flag.txt
aUctf_{h3y_th3_fl4g}
user@pyshell$ cat .acl.txt
auctf{h4_y0u_g0t_tr0ll3d_welC0m#_t0_pWN_l@nd}
```

