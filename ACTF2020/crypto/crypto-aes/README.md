## aes

- key长32字节，为两字节随机数重复16次，iv长16字节
- 已知：输出out，key与iv异或的结果
- 由于key与iv长度不一样，key有16字节字节与0异或，还是其本身，因此可解出key
- 由异或结果可解出iv

- 解出iv后，直接aes解密即可

  ```python
  #!/usr/bin/python3
  #__author__:TaQini
  
  from Crypto.Cipher import AES
  import os
  import gmpy2
  from Crypto.Util.number import *
  
  out = long_to_bytes(91144196586662942563895769614300232343026691029427747065707381728622849079757)
  
  key = out[:16]*2
  
  xor_res = out[16:]
  
  iv = bytes_to_long(xor_res)^bytes_to_long(key[16:])
  iv = long_to_bytes(iv)
  
  aes=AES.new(key,AES.MODE_CBC,iv)
  
  out = b'\x8c-\xcd\xde\xa7\xe9\x7f.b\x8aKs\xf1\xba\xc75\xc4d\x13\x07\xac\xa4&\xd6\x91\xfe\xf3\x14\x10|\xf8p'
  
  flag = aes.decrypt(out)
  
  print(flag)
  ```

  