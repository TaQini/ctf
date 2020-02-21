## Ridicule_Revenge

- 题目描述：

  > 在你破解了Alice和Bob的通信后，他们决定不再把一条消息发送两次。他们认为，这次你一定束手无策。于是还是为了嘲讽你，他们甚至公开了加密脚本！ 
  >
  > By *scholze*

 - [题目附件](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Crypto/RidiculeRevenge/attachment.zip)

 - 考察点：RSA攻击

 - 难度：中等

 - 初始分值：250

 - 最终分值：212

 - 完成人数：7

>  好像是个原题，能做出来全靠百度。

### 加密

```python
while True:
    p = int(gmpy2.next_prime(random.randint(10**399, 10**400-1)))
    q = int(str(p)[200:]+str(p)[:200])
    if gmpy2.is_prime(q):
        print "not right",p,q
        if check(p*q):
            print p*q
```

p和q的选取比较有意思:

> p是长度400的随机素数，然后将p的前后200位互换位置，如果结果还是素数的话就作为q

### 思路

摘录自[参考链接](https://www.jianshu.com/p/763427ea0e4b)

> 首先我们先把![p](https://math.jianshu.com/math?formula=p)切割成两部分，前200位为![a](https://math.jianshu.com/math?formula=a)，后面的为![b](https://math.jianshu.com/math?formula=b)，则![p=a*10^{200}+b](https://math.jianshu.com/math?formula=p%3Da*10%5E%7B200%7D%2Bb)，此时![q=b*10^{200}+a](https://math.jianshu.com/math?formula=q%3Db*10%5E%7B200%7D%2Ba)。
>  所以![n=p*q=(b*10^{200}+a)*(a*10^{200}+b)=(a*b*10^{400}+(b^2+a^2)*10^{200}+a*b)](https://math.jianshu.com/math?formula=n%3Dp*q%3D(b*10%5E%7B200%7D%2Ba)*(a*10%5E%7B200%7D%2Bb)%3D(a*b*10%5E%7B400%7D%2B(b%5E2%2Ba%5E2)*10%5E%7B200%7D%2Ba*b))不难发现![n](https://math.jianshu.com/math?formula=n)最低200位是![a*b](https://math.jianshu.com/math?formula=a*b)的低200位，![n](https://math.jianshu.com/math?formula=n)最高200位是![a*b](https://math.jianshu.com/math?formula=a*b)的高200位（或者![a^2+b^2](https://math.jianshu.com/math?formula=a%5E2%2Bb%5E2)进一位）而![p](https://math.jianshu.com/math?formula=p)是400位，所以![a,b](https://math.jianshu.com/math?formula=a%2Cb)都为200位，所以![a*b](https://math.jianshu.com/math?formula=a*b)也为400位，所以此时得到就是![a*b](https://math.jianshu.com/math?formula=a*b)。
>  此时我们用![a*b](https://math.jianshu.com/math?formula=a*b)去代入上述等式，求出![(a^2+b^2)*10^{200}](https://math.jianshu.com/math?formula=(a%5E2%2Bb%5E2)*10%5E%7B200%7D)。此时我们可以根据得到的值后200位是否全为0，从而判断![a^2+b^2](https://math.jianshu.com/math?formula=a%5E2%2Bb%5E2)是进了一位的。然后两个变量两个等式算出![a](https://math.jianshu.com/math?formula=a)，![b](https://math.jianshu.com/math?formula=b)。

### 解密

```python
# https://www.jianshu.com/p/763427ea0e4b
import gmpy2
from Crypto.Util.number import *

c = 16396023285324039009558195962852040868243807971027796599580351414803675753933120024077886501736987010658812435904022750269541456641256887079780585729054681025921699044139927086676479128232499416835051090240458236280851063589059069181638802191717911599940897797235038838827322737207584188123709413077535201099325099110746196702421778588988049442604655243604852727791349351291721230577933794627015369213339150586418524473465234375420448340981330049205933291705601563283196409846408465061438001010141891397738066420524119638524908958331406698679544896351376594583883601612086738834989175070317781690217164773657939589691476539613343289431727103692899002758373929815089904574190511978680084831183328681104467553713888762965976896013404518316128288520016934828176674482545660323358594211794461624622116836
n = 21173064304574950843737446409192091844410858354407853391518219828585809575546480463980354529412530785625473800210661276075473243912578032636845746866907991400822100939309254988798139819074875464612813385347487571449985243023886473371811269444618192595245380064162413031254981146354667983890607067651694310528489568882179752700069248266341927980053359911075295668342299406306747805925686573419756406095039162847475158920069325898899318222396609393685237607183668014820188522330005608037386873926432131081161531088656666402464062741934007562757339219055643198715643442608910351994872740343566582808831066736088527333762011263273533065540484105964087424030617602336598479611569611018708530024591023015267812545697478378348866840434551477126856261767535209092047810194387033643274333303926423370062572301
e = 65537
tmp = 10**200
#abhigh,ablow = n/(tmp^3), n % tmp
abhigh,ablow = n/(tmp**3)-1, n % tmp
ab = abhigh*tmp+ablow
# a**2+b**2
a2b2 = (n-ab*(tmp**2)-ab)/tmp
#print a2b2
#(a-b),(a+b)
tmp1 = gmpy2.iroot(a2b2-2*ab,2)[0]
tmp2 = gmpy2.iroot(a2b2+2*ab,2)[0]
a = (tmp1+tmp2)/2
b = a-tmp1
p = a*tmp + b
q = n/p
phi = (p-1)*(q-1)
d = gmpy2.invert(e,phi)
m = pow(c,d,p*q)
print long_to_bytes(m)
```

