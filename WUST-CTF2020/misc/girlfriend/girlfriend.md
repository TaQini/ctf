## girlfriend

链接: https://pan.baidu.com/s/1_mDokFTuHlscTkV1P6cZ3w 提取码: e5y3
 I want a girl friend !!!
将结果用wctf2020{}再提交



百度搜到这篇文章:[听按键音识手机号 - DTMF](https://gamous.cn/index.php/archives/43/)

**DTMF**(**D**ual-**T**one **M**ulti-**F**requency) 即双音多频信号，通过两个频率信号的叠加的方式传递信息。较脉冲信号而言，这种信号传递时稳定便捷，被用于电话系统的拨号信号。

如今，手机也大多默认以 DTMF 的声音作为拨号界面的按键音。因此，只要分析按键音即可从中识别到对应的号码。

|           | 1209Hz | 1336Hz | 1477Hz | 1633Hz |
| --------- | ------ | ------ | ------ | ------ |
| **697Hz** | 1      | 2      | 3      | A      |
| **770Hz** | 4      | 5      | 6      | B      |
| **852Hz** | 7      | 8      | 9      | C      |
| **941Hz** | *      | 0      | #      | D      |

一个高信号与低信号叠加表示 4*4 棋盘上的信号，在频谱中显示为上下俩条水平密集线，经过 FFT 变换可得到两个笔直波峰。

傅里叶变换貌似在大学数据采集课上学过，于是尝试了一下。。。这也太复杂了！放弃。。数学太难了。

然后开心地在Audacity菜单栏找到了频谱分析功能~~~

![](http://image.taqini.space/img/20200328034046.png)

对每个按键音进行频谱分析，可以得到两个信号频率值(图中峰值)，查**DTMF**表即可解得相应数字/字母。

后来在github上找到了一个七年前的脚本 [dtmf-decoder.py](https://github.com/hfeeki/dtmf/blob/master/dtmf-decoder.py) (还能用)，跑出来一串神秘数字：

``` python
999*666*88*2*777*33*6*999*4*444*777*555*333*777*444*33*66*3*7777
```

看了半天，也不知道这是神马玩意。乘法算式么？于是卡住了，就去做其他题了。

后来我拿起手机，灵机一动！这不是T9键盘么(“▔□▔)`

![](http://image.taqini.space/img/65E524BBA435784B11AB8FA892CB614D.jpg)

数字重复三次表示按键按下了三次，选择相应的字母....最终解得：
``` 
YOUAREMYGIRLFRIENDS
```

> flag:  wctf2020{youaremygirlfriends}

这题太有意思了叭。。。



![](http://image.taqini.space/img/20200328042930.png)