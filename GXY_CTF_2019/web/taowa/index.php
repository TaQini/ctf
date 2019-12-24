<?php
include "flag.php";
echo "flag在哪里呢？<br>";
if(isset($_GET['exp'])){
	if (!preg_match('/data:\/\/|filter:\/\/|php:\/\/|phar:\/\//i', $_GET['exp'])) {
		if(';' === preg_replace('/[a-z|\-]+\((?R)?\)/', NULL, $_GET['exp'])) {
			if (!preg_match('/et|na|nt|info|dec|bin|hex|oct|pi|log/i', $code)) {
				// echo $_GET['exp'];
				eval($_GET['exp']);
			}
			else{
				die("还差一点哦！");
			}
		}
		else{
			die("再好好想想！");
		}
	}
	else{
		die("还想读flag，臭弟弟！");
	}
}
// highlight_file(__FILE__);
?>