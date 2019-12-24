#/usr/bin/python 
#__author__: TaQini

from pwn import * 

i0 = 0x3E3A4717373E7F1F - 0x11204161012 
i1 = 0x0 # unknow 
i2 = 0x8020717153E3013 
i3 = 0x3E3A4717373E7F1F ^ 0x3E3A4717050F791F # 0x32310600

# print hex(i0),hex(i2),hex(i3)
s0 = "i_will_check_is_debug_or_not" 
s1 = p64(i0,endianness='big')+p64(i1,endianness='big')+p64(i2,endianness='big')+p32(i3,endianness='big') 

flag = '' 
for i in range(len(s0)): 
    if i<7 or i>15: 
        flag += chr(ord(s0[i])^ord(s1[i])) 
    know = 'e!P0or_a' 
    if i==8: 
        flag += know 

print flag 

