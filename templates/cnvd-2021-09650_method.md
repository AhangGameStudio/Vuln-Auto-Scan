# 锐捷 NBR路由器 远程命令执行漏洞 CNVD-2021-09650

## 漏洞描述
锐捷NBR路由器 EWEB网管系统部分接口存在命令注入，导致远程命令执行获取权限

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
![](images/202202110923377.png)

出现漏洞的文件在 **/guest_auth/guestIsUp.php**

```php
<?php
    //查询用户是否上线了
    $userip = @$_POST['ip'];
    $usermac = @$_POST['mac'];
    

## Payloads
```
这里看到通过命令拼接的方式构造命令执行，
```
