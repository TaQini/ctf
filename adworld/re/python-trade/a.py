# uncompyle6 version 3.6.2
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.7.3 (default, Oct  7 2019, 12:56:13) 
# [GCC 8.3.0]
# Embedded file name: 1.py
# Compiled at: 2017-06-03 10:20:43
import base64

def encode(message):
    s = ''
    for i in message:
        x = ord(i) ^ 32
        x = x + 16
        s += chr(x)

    return base64.b64encode(s)


correct = 'XlNkVmtUI1MgXWBZXCFeKY+AaXNt'
flag = ''
print 'Input flag:'
flag = raw_input()
if encode(flag) == correct:
    print 'correct'
else:
    print 'wrong'
# okay decompiling ./f417c0d03b0344eb9969ed0e1f772091.pyc

def decode(msg):
    s = ''
    for i in msg:
        x = ord(i)
        x = x - 16
        x = x ^ 32
        s += chr(x)
    return s

