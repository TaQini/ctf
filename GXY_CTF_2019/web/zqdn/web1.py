#!/usr/bin/python3
#__author__:TaQini
import requests

# header
s=requests.session()                                     
s.headers['Accept']='text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'
s.headers['Accept-Encoding']='gzip, deflate, br'
s.headers['Host']='url'                 
s.headers['Accept-Language']='zh-CN,zh;q=0.9,en;q=0.8,ja;q=0.7,ko;q=0.6'
s.headers['User-Agent']='zilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36'

url = 'http://172.21.4.12:3333/index.php'

# post
def p(n):                          
	num = n                
	res = s.post(url=url,data={'answer':n})
	res.encoding = res.apparent_encoding
	return res.text 

# calc
def suan(t):                       
	k = t.split('<br><br>')
	v = eval(k[2])      
	return v 

# init
t = p(2333)

for i in range(1001): 
	t = p(suan(t))
	print(t)
