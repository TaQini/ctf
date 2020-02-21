## Rabbit Hole

- 题目描述：

  > 一只奇怪的兔子钻进洞里啦，赶紧把它揪出来。 
  >
  > http://rabbit.yoshino-s.org/ 
  >
  > By *Yoshino-s*

 - 考察点：dig命令、rabbit加密

 - 难度：简单

 - 初始分值：100

 - 最终分值：62

 - 完成人数：9

访问网页，得到提示：

> To catch the rabbit, you should dig deeper and find the txt.

用dig命令查询这个题目url的TXT记录：

```shell
$ dig -t TXT rabbit.yoshino-s.org

; <<>> DiG 9.11.5-P1-1ubuntu2.6-Ubuntu <<>> -t TXT rabbit.yoshino-s.org
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54090
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;rabbit.yoshino-s.org.		IN	TXT

;; ANSWER SECTION:
rabbit.yoshino-s.org.	300	IN	TXT	"U2FsdGVkX18BkpB/W9lD7ZGSP5BprjbrL/WKn+7fn8gWCXpmDW+y/5FoVYPd5pIFCZfHFiov"

;; Query time: 192 msec
;; SERVER: 127.0.0.53#53(127.0.0.53)
;; WHEN: 四 2月 20 20:30:40 CST 2020
;; MSG SIZE  rcvd: 134

```

在`ANSWER SECTION:`中得到密文，[Rabbit解密](https://www.sojson.com/encrypt_rabbit.html)后即为flag

> flag{0d23348ede942398962778bf49c59776}