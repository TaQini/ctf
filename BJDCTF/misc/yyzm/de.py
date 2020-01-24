import binascii
import struct
crc32key = 0xc20f1fc6
for i in range(0, 65535):
    height = struct.pack('>i', i)
    data = '\x49\x48\x44\x52\x00\x00\x01\x41' + height + '\x08\x06\x00\x00\x00'
    crc32result = binascii.crc32(data) & 0xffffffff
    if crc32result == crc32key:
        print ''.join(map(lambda c: "%02X" % ord(c), height))

# 0000034C
