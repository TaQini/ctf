#!/usr/bin/python
#-*-coding:utf-8-*-
#__author__:TaQini

import os
from pwn import *

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
          
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('./Pwn', os.F_OK): os.mkdir('./Pwn')
            path = './Pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)

context.log_level='debug'

# elf, libc
elf=change_ld('./crap','./lib/ld-linux-x86-64.so.2')
if len(sys.argv)>1:
    is_remote=True
    p = remote('asia.crap.tghack.no','6001')
else:
    is_local=True
    p = elf.process(env={'LD_PRELOAD':'./lib/libc.so.6','LD_LIBRARY_PATH':'lib'})
libc = ELF('./lib/libc.so.6')

# raw_input()
p.interactive()
