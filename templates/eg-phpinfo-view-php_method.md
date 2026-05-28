# 锐捷 EG易网关 phpinfo.view.php 信息泄露漏洞

## 漏洞描述
锐捷EG易网关 部分版本 phpinfo.view.php文件权限设定存在问题，导致未经身份验证获取敏感信息

## 危害等级
MEDIUM

## 参考链接

## 漏洞复现方法
查看源码发现phpinfo文件

![](images/202202110927256.png)

访问 url

```plain
/tool/view/phpinfo.view.php
```

