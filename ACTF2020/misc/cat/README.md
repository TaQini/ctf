## 喵咪

- 根据提示百度了下，是outguess加密

- 直接解密的话报错了，看来是需要key

- windows下查看图片属性，备注里有着**社会主义核心价值观**

- 送去[这里](http://ctf.ssleye.com/cvencode.html)解码，解得`abc`

- 用key解密即可：

  ```shell
  % ./outguess -r mmm.jpg -k abc -t a.txt ; cat a.txt
  Reading mmm.jpg....
  Extracting usable bits:   17550 bits
  Steg retrieve: seed: 93, len: 23
  ACTF{gue33_Gu3Ss!2020}
  ```

  