# coding:utf-8
# Author: ynm3000 https://ctf.show
# 2020/3/16

import requests
import json
import operator

pre_url = 'https://ctf.show/api/v1/challenges/'
chall_dyn = [287,289,290,293,294,295,296,297,298,300,301,302,303,304,305,306,307,308,309,310,312,313,314,316,317,318,319]
chall_cat={'WEB':[289,295,303,304,308,310],
            'PWN':[287,290,294,296,300,307],
            'CRYPTO':[293,318,319],
            'REVERSE':[297,298,312,313],
            'MISC':[301,302,305,306,309,314,316,317]}
chall_count=0
for category in chall_cat:
    chall_count+=len(chall_cat[category])
print(chall_count)
# chall_dyn = [192, 194, 195, 196]
end_url = '/solves'
dic = {}

# （初始分数-最低分数）x （下降率+1）/（做对人数+下降率）÷ 最低分数
init_score = 1000
min_score = 0
decay = 9
right_number = 0

bonus_score=[1.05,1.03,1.01,1]
# 动态题目积分
#mycookie={"session":'9ed48c7e-0591-47bf-b56d-cc41375283d1._CIGN8v-ed2vHc4vcV9T6jN7zQA'}
for category in chall_cat:
    print(category,end="")
    print("-"*(40-len(category)))
    for num in chall_cat[category]:
        #res = requests.get(pre_url + str(num) ,cookies=mycookie)
        res = requests.get(pre_url + str(num))
        challenge=json.loads(res.text)['data']
        chall_name=json.loads(res.text)['data']['name']
        res = requests.get(pre_url + str(num) + end_url)
        players = json.loads(res.text)['data']
        temp_score = min((init_score-min_score)*(decay+1)/(len(players)+decay)+min_score,init_score)
        #print(res.text)
        
        print("%4d %3d solved  %s"%(int(temp_score),len(players),chall_name))
        count=0
        for s in players:
            if(count>=len(bonus_score)):
                ttemp_score=int(temp_score*bonus_score[-1])
            else:
                ttemp_score=int(temp_score*bonus_score[count])
            if dic.get(s['name']):
                dic[s['name']] = int(dic[s['name']]) + ttemp_score
            else:
                dic[s['name']] = ttemp_score
            count+=1

dic = sorted(dic.items(), key=operator.itemgetter(1), reverse=True)
print("Ranking---------------------------------")
r=1
with open('score.txt', 'w') as f:
    for s in dic:
        strings = str(r).ljust(3)+'\t'+str(s[1]).ljust(5)+s[0]
        f.write(strings+'\n')
        print(strings)
        r+=1
