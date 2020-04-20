## Suckmore Shell 2.0 (200pt)

### Description

> After its abysmal performance at WPICTF  2019, suckmore shell v1 has been replaced with a more secure, innovative and performant version, aptly named suckmore shell V2. 
>
> `ssh smsh@smsh.wpictf.xyz` pass: `suckmore>suckless` 
>
> made by: acurless

### Solution

Here are some kinds of cmd can use to leak content of files:

* file viewer (`more`)
* compress/decompress cmd (`xz`, `tar`, `bzip2`)
* Language interpreter/assembler (`perl`, `as` )

#### File viewer

Use `more` command to view flag directly:
```bash
> more flag
echo "WPI{SUckmoreSoftwareN33dz2G3TitTogeTHER}"
```

#### Compress/decompress

Some cmd (with or without options) can print content of file during compress/decompress process

```bash
> xz flag
�7zXZ�ִF!t/�/echo "WPI{SUckmoreSoftwareN33dz2G3TitTogeTHER}"
�r����`�H0�@�>��}YZ> ls
```

```bash
> tar cvf a.tar flag
flag
> tar xvf a.tar
flag
echo "WPI{SUckmoreSoftwareN33dz2G3TitTogeTHER}"
```

```bash
> bzip2 flag
> bzip2 -c -d flag.bz2
echo "WPI{SUckmoreSoftwareN33dz2G3TitTogeTHER}"
```

#### Language interpreter/assembler

Error information of language interpreter/assembler may print the content of files:

```bash
> perl flag
String found where operator expected at flag line 1, near "echo "WPI{SUckmoreSoftwareN33dz2G3TitTogeTHER}""
    (Do you need to predeclare echo?)
syntax error at flag line 1, near "echo "WPI{SUckmoreSoftwareN33dz2G3TitTogeTHER}""
Execution of flag aborted due to compilation errors.
```

```bash
> as flag
flag: Assembler messages:
flag:1: Error: no such instruction: `echo "WPI{SUckmoreSoftwareN33dz2G3TitTogeTHER}"'
```
