# 皓峰防火墙 setdomain.php 越权访问漏洞

## 漏洞描述
皓峰防火墙 setdomain.php 页面存在越权访问漏洞，攻击者通过漏洞可修改管理员等配置信息

## 危害等级
LOW

## 参考链接

## 漏洞复现方法
登录页面

![img](images/202202110917093.png)

验证POC

```php
/setdomain.php?action=list
```

