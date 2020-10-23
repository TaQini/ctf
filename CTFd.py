#!/usr/bin/python 
#coding: utf-8

flag = '''
# web
最简单的web 68 NYSEC{We_like_f12} F12
MD5碰撞 11 NYSEC{Md5_1S_s0_fuN!!!!!} http://47.114.103.104:116/Web_2/Web_2.php?str=s214587387a
矛盾 4 NYSEC{OK_flllaag_1s_here!!!} http://47.114.84.225:10080/?num=1'
曲奇饼！ 28 NYSEC{This_1s_your_f1ag} xxf+referer

# misc
文盲加密 25 NYSEC{我不是文盲} https://pinyin.supfree.net/
简单签个到 2 NYSEC{Welc0me_2_NYSEC} http://nysec.cn/
小黄鸭 23 NYSEC{GIFISSOFUN}
base家族 30 NYSEC{zxxcsadw} pwd:3862,base64-qrcode->R,;dcv}6QV[xdQbj[]D-base91->NYSEC{zxxcsadw}

# re
ezreverse 3 NYSEC{Reverse_1s_Ea5y} 0x004015bd-0x004015e0
cmd 39 NYSEC{fl@g_1s_Soooo_fun!!!} rabin2 -zz 2.cmd.exe|grep NY
'''

import requests

url = 'http://nysec.cn/api/v1/challenges/attempt'

headers = {
'Host': 'nysec.cn',
'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0',
'Accept': 'application/json',
'Accept-Language': 'en-US,en;q=0.5',
'Accept-Encoding': 'gzip, deflate',
'Referer': 'http://nysec.cn/challenges',
'Content-Type': 'application/json',
'CSRF-Token': 'eae1c717c9b5c01fff24a168ef5786ec3e58adefd4437fd1afe7eebcce651444',
'Origin': 'http://nysec.cn',
'Connection': 'close',
'Cookie': 'UM_distinctid=17548d6eb1a38f-0cab9f41cf49bb-7925675c-1fa400-17548d6eb1c550; CNZZDATA1279202668=1509233257-1603244842-%7C1603252650; session=faa510fa-e231-4a17-9194-923419b7c483.XNcAQQbFp47oAcUl9MhVmsYFntw'
}

for i in flag.split('\n'):
    if '{' in i:
        name,id,flag = i.split()[:3]
        print name,id,flag,
        json = {
            "challenge_id":id,
            "submission":flag
        }
        a = requests.post(url=url,json=json,headers=headers)
        print a.json()['data']['message']
