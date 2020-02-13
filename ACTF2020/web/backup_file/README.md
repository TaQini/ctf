## 21001

提示`Try to find out source file!`，于是扫一下目录发现`index.php.bak`:

```php
<?php
include_once "flag.php";

if(isset($_GET['key'])) {
    $key = $_GET['key'];
    if(!is_numeric($key)) {
        exit("Just num!");
    }
    $key = intval($key);
    $str = "123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3";
    if($key == $str) {
        echo $flag;
    }
}
else {
    echo "Try to find out source file!";
}
```
`$key == $str`时给`flag`

`key`必须是数字，而`str`是字符串

由于php弱类型，`str`在比较时`"123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3"=123`

所以`key=123`即可绕过比较

exp:

```http
http://106.15.207.47:21001/?key=123
```