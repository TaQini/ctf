## Ridicule_Rerevengevenge [unsolved]

- 题目描述：

  > 在你再次成功破解他们的通信之后，Alice和Bob依然没有停止对你的嘲讽——这一次，你甚至可以得到残缺的明文！ 
  >
  > 注：flag为明文的隐藏部分，flag格式为`flag{16进制数}` 
  >
  > By *scholze*
  >
  > hint: Sage

 - [题目附件](https://cdn.jsdelivr.net/gh/SignorMercurio/MetasequoiaCTF@master/Crypto/RidiculeRerevengevenge/attachment.zip)

 - 考察点：RSA攻击

 - 难度：困难

 - 初始分值：400

 - 最终分值：368

 - 完成人数：5

> 数学...太南了...看官方wp给的[参考链接](https://code.felinae98.cn/ctf/crypto/rsa%E5%A4%A7%E7%A4%BC%E5%8C%85%EF%BC%88%E4%BA%8C%EF%BC%89coppersmith-%E7%9B%B8%E5%85%B3/)竟是我本科社团学弟的文章...唉...自愧不如......

### 直接贴出官方wp

去[这里](https://sagecell.sagemath.org/)，选择`sage`，然后参考[这篇文章](https://code.felinae98.cn/ctf/crypto/rsa大礼包%EF%BC%88二%EF%BC%89coppersmith-相关)

转成十进制后再用如下代码：
```python
n = 0x2519834a6cc3bf25d078caefc5358e41c726a7a56270e425e21515d1b195b248b82f4189a0b621694586bb254e27010ee4376a849bb373e5e3f2eb622e3e7804d18ddb897463f3516b431e7fc65ec41c42edf736d5940c3139d1e374aed1fc3b70737125e1f540b541a9c671f4bf0ded798d727211116eb8b86cdd6a29aefcc7
e = 3
m = randrange(n)
c = pow(m, e, n)
beta = 1
epsilon = beta ^ 2 / 7
nbits = n.nbits()
kbits = floor(nbits * (beta ^ 2 / e - epsilon))
# mbar = m & (2^nbits-2^kbits)
mbar = 0xb11ffc4ce423c77035280f1c575696327901daac8a83c057c453973ee5f4e508455648886441c0f3393fe4c922ef1c3a6249c12d21a000000000000000000
c = 0x1f6f6a8e61f7b5ad8bef738f4376a96724192d8da1e3689dec7ce5d1df615e0910803317f9bafb6671ffe722e0292ce76cca399f2af1952dd31a61b37019da9cf27f82c3ecd4befc03c557efe1a5a29f9bb73c0239f62ed951955718ac0eaa3f60a4c415ef064ea33bbd61abe127c6fc808c0edb034c52c45bd20a219317fb75
#print "upper %d bits (of %d bits) is given" % (nbits - kbits, nbits)
PR.<x> = PolynomialRing(Zmod(n))
f = (mbar + x) ^ e - c
m
x0 = f.small_roots(X=2 ^ kbits, beta=1)[0]  # find root < 2^kbits with factor = n1
mbar + x0
```

解得:
```
0xb11ffc4ce423c77035280f1c575696327901daac8a83c057c453973ee5f4e508455648886441c0f3393fe4c922ef1c3a6249c12d21a4a8c1d4dec4a0e9bf1
```
则对比原来的16进制发现flag为`flag{4a8c1d4dec4a0e9bf1}`。