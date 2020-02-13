## usualCrypt

​	输入字符串，经过自定义的base64加密后，与密文比对

​	解密密文即flag

### DIY base64 encode

- base64换表

  ```c
  signed int swap_Base_table()
  {
    signed int result; // eax
    char tmp; // cl
  
    result = 6;
    do
    {
      tmp = array_2[result];
      array_2[result] = array_1[result];
      array_1[result++] = tmp;
    }
    while ( result < 15 );
    return result;
  }
  ```

- base64加密

- 密文大小写互换

  ```c
  int __cdecl swap_Upper_Lower(const char *buf)
  {
    __int64 i; // rax
    char chr; // al
  
    i = 0i64;
    if ( strlen(buf) != 0 )
    {
      do
      {
        chr = buf[HIDWORD(i)];
        if ( chr < 97 || chr > 122 )
        {
          if ( chr < 65 || chr > 90 )
            goto LABEL_9;
          LOBYTE(i) = chr + 0x20;
        }
        else
        {
          LOBYTE(i) = chr - 0x20;
        }
        buf[HIDWORD(i)] = i;
  LABEL_9:
        LODWORD(i) = 0;
        ++HIDWORD(i);
      }
      while ( HIDWORD(i) < strlen(buf) );
    }
    return i;
  }
  ```


### 解密

- 生成base64编码表

  ```c
  char array[] = "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x2B\x2F\x00";
  
  char *array_1 = array;
  char *array_2 = array+10;
  
  signed int swap()
  {
    signed int result; // eax
    char v1; // cl
  
    result = 6;
    do
    {
      v1 = array_2[result];
      array_2[result] = array_1[result];
      array_1[result++] = v1;
    }
    while ( result < 15 );
    return result;
  }
  
  int main(){
      printf("%s\n",array);
      //printf("%s\n",array_1);
      //printf("%s\n",array_2);
      swap();
      printf("%s\n",array);
      //printf("%s\n",array_1);
      //printf("%s\n",array_2);
  }
  ```

- 密文大小写互换

    ```python
    #!/usr/bin/python
    #__author__:TaQini

    enced = [0x7A, 0x4D, 0x58, 0x48, 0x7A, 0x33, 0x54, 0x49, 0x67, 0x6E, 0x78, 0x4C, 0x78, 0x4A, 0x68, 0x46, 0x41, 0x64, 0x74, 0x5A, 0x6E, 0x32, 0x66, 0x46, 0x6B, 0x33, 0x6C, 0x59, 0x43, 0x72, 0x74, 0x50, 0x43, 0x32, 0x6C, 0x39]
    chipertext = ''.join([chr(i) for i in enced])

    print chipertext

    # swap uppercase and lowercase
    def swapUL(buf):
        tmp = ''
        for i in buf:
            c = ord(i)
            if c < 97 or c > 122:
                if c < 65 or c > 90:
                    tmp += i
                    continue
                tmp += chr(c+0x20)
            else:
                tmp += chr(c-0x20)
        return tmp

    newc = swapUL(chipertext)
    print newc
    ```

- 进行base64解密

    ```python
    table = "ABCDEFQRSTUVWXYPGHIJKLMNOZabcdefghijklmnopqrstuvwxyz0123456789+/"
    print table

    l=[]
    for i in newc:
        l.append(table.index(i))
    # print l

    s=''
    for i in l:
        b = bin(i)[2:].rjust(6,'0')
        s += b
        # print(b)
    # print s

    h = hex(int(s,2))[2:-1]
    # print h
    print h.decode('hex')
    ```

