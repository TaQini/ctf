## game

- 数独游戏，主要代码如下：

  ```c
    abc_to_num(user_input);
    fill_map(user_input, &map);
    check_map(&map);
    puts("Congratulations, you successfully solved this little problem!");
    printf(aFlag, buf);
  ```

  将输入的`abcdefghi`转成数字`123456789`，然后按顺序填到棋盘中

  最后分别检查每行、每列、每个九宫格内的数字是否合法

- 这题只要分析出是数独游戏就好办了，`fill_map`这个函数中有个循环跑了81次，`check_map`函数中又有`9x9`的循环，由此可以想到这是个`9x9`的二维数组，到这里差不多就知道是数独了，dump出棋盘，玩儿一局数独就能拿到flag，美滋滋~

- 棋盘：

  ```c
  2 5 0 1 4 0 6 8 9 
  0 0 8 9 0 6 2 0 5 
  6 7 9 2 5 8 1 4 3 
  3 1 2 5 8 4 7 0 0 
  0 8 0 7 9 0 5 3 2 
  5 9 7 0 6 2 8 1 0 
  7 2 4 0 1 3 0 5 8 
  8 6 5 4 7 9 3 0 1 
  9 3 1 8 2 5 4 0 0 
  ```

- 脚本：

  ```python
  #!/usr/bin/python
  #__author__:TaQini
  
  codemap_s = '2 5 0 1 4 0 6 8 9 0 0 8 9 0 6 2 0 5 6 7 9 2 5 8 1 4 3 3 1 2 5 8 4 7 0 0 0 8 0 7 9 0 5 3 2 5 9 7 0 6 2 8 1 0 7 2 4 0 1 3 0 5 8 8 6 5 4 7 9 3 0 1 9 3 1 8 2 5 4 0 0'
  codemap = codemap_s.split()
  
  def show():
      cnt = 0 
      cnt0 = 0
      for i in codemap:
          if i=='0':
              cnt0 += 1
          cnt += 1
          print i,
          if cnt %9==0:
              print ''
      print 'count of 0: %s'%cnt0
  show()
  
  user = [3,7,1,4,3,7,9,6,4,6,1,3,4,6,9,2,6,7]
  
  print user
  
  new_map = []
  
  pos = 0
  for i in codemap:
      if i == '0' and pos < len(user):
          new_map.append(str(user[pos]))
          pos += 1
      else:
          new_map.append(i)
  
  flag = []
  for i in user:
      flag.append(chr(i+96))
  
  codemap = new_map
  show()
  
  print "flag{%s}"%''.join(flag)
  ```

  

- p.s.数独真好玩儿